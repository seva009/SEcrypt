//build commands
//Linux : g++ main.cpp md5.cpp -lncurses -O2 -Wall -std=c++11 -D__linux__
//Windows : g++ main.cpp md5.cpp -O2 -Wall -std=c++11 -D_WIN32
/*
classname.init(...) это загрузка файла в ОЗУ, генерация ключей
classname.crypt() XOR'ит файл с ключами
classname.saveFile() ну тут все понятно
classname.wipe() затирает ключи и файл и деалокейтит их
classname.clear() старая версия, затирает файл и деалокейтит его (в новой версии функционал включен в classname.wipe())
*/
/*
 А вот размышления о (-xs -lm -up) вместе 
 Мощность моей мультиварки (в гугле) 3.258 MFLOPS 
 Скорость генерации ~2560000  рандом чисел 0.1 сек или 100мс
 т.е. за 1 мс генерируется 2560 рандомных чисел
 Мощность суперкомпа от яндекс 21.53 квдр FLOPS aka 21530000000000000 FLOPS (мой 3258000 FLOPS)
 21530000000000000 / 3258000 = 6608348680,2 раза ск мощнее моей мв
 ~= 6,6 млрд раз т.е за мс генерит 1,6917 * 10^13 рандомных чисел
 возьмем зашифрованый  exe'шник по сигнатуре  MZ мы найдем первые 2 байта ключа
 2^32 / 2^8 = 16777216 столько ключей даст правильный символ
 возведем в квадрат чтобы получить все вариации = 2,815 * 10^14
 и если exe весит 100000 байт то надо сгенерировать 5,63 * 10^19 рандомных байт
 5,63 * 10^19 / 1,6917 * 10^13 = 333000 мс или 333 сек(но без учета XORa записи и т.д проверки на валидность)
 и можно смело домножать на 100 примерно выходит 9,25 часа (но если например взять архив и накидать
 туда мусора так на гб 60 то выйдет около 60 лет но это уже другая история)
 и если ты не шпион из анб то будут дешифровывать на ноуте максимум и это займет сотни лет 
 так вот все расчеты проведены для 4 ключей а о 8 думаю говорить не надо
 а если для тебя это не аргумент то просто флаг -t делает взлом невозможным(но надо хранить ключ где-то)
*/
#include "rsa.hpp"
#include "tracealloc.h"
#include "dFile.h"
#include "aes256.hpp"
#include <stdio.h>
#include "crypt.h"
#include "httplib.h"
#include <cstring>

#ifdef __linux__
    #include <ncurses.h> // заголовок для линукс
#elif defined(_WIN32)
    #include <conio.h> // и для винды
    #include <string>

    #include <cstdlib>

#endif

#define PASSWORD_LEN 256 //максимальная длина пароля чтобы небыло переполнения
//названия флагов
const char* lmflags[]    = {"-lm", "-l", "--low-memory"};
const char* xsflags[]    = {"-xs", "-x", "--xs-mode"};
const char* hflags[]     = {"-h", "-hp", "--help"};
const char* u2pflags[]   = {"-up", "-u", "--u2p-mode"};
const char* utrflags[]   = {"-tr", "-t", "--ut-mode"};
const char* uekflags[]   = {"-ek", "-e", "--uek-mode"};
const char* aesflags[]   = {"-a", "-aes", "--aes-mode"};
const char* serveflags[] = {"-s", "-sv", "--serve"};


int do_serve(void) {
    httplib::Server svr;
    svr.Get("/getmemuse", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(std::to_string(t.getAllocSz()), "text/plain");
    });

    svr.Get("/", [](const httplib::Request &, httplib::Response &res) {
        res.set_file_content("./index.html");
    });
    svr.Post("/process", [](const httplib::Request &req, httplib::Response &res) {
        auto size = req.files.size();
        const auto& file = req.get_file_value("file");
        const auto& password = req.get_file_value("password");
        const auto& rsa_key = req.get_file_value("rsa_key");
        const auto& algo = req.get_file_value("algorithm");
        const auto& action = req.get_file_value("action");
        string outs;
        if (algo.content == "aes256") {
            ByteArray key, plain, out;
            size_t endSize;
            for (auto c : password.content) {
                key.push_back(c);
            }
            for (auto c : file.content) {
                plain.push_back(c);
            }
            Aes256 aes(key);
            if (action.content == "encrypt") {
                endSize = Aes256::encrypt(key, plain, out);
            }
            else {
                endSize = Aes256::decrypt(key, plain, out);
            }
            for (int i = 0; i < endSize; ++i) {
                outs.push_back(out[i]);
            }
        } else if (algo.content == "rsa") {
            if (action.content == "encrypt") {
                RSA rsa(PublicKey::deserialize(rsa_key.content));
                outs = rsa.encrypt(file.content);
            } else {
                RSA rsa(PrivateKey::deserialize(rsa_key.content));
                outs = rsa.decrypt(file.content);
            }
        }
        res.set_content(outs, "application/octet-stream");
    });
    svr.Get("/generate_rsa_key", [](const httplib::Request &req, httplib::Response &res) {
        RSA rsa(256);  // Hard coded
        std::string out;
        out.append("{\"private_key\": \"");
        out.append(rsa.private_key.serialize());
        out.push_back('"');
        out.append(", \"public_key\": \"");
        out.append(rsa.public_key.serialize());
        out.append("\"}");
        res.set_content(out, "application/json");
    });


    svr.listen("127.0.0.1", 23444);
    return 0;
}


int main(int argc, char *argv[])
{
    /*сами флаги*/
    bool lm = false;
    bool xs = false;
    bool h = false;
    bool u2p = false;
    bool utr = false;
    bool uek = false;
    bool aes = false;
    bool serve = false;
    int ekpos = 0;

    printf("SEcrypt by Empers0n_ \n");

    //пароли с размером PASSWORD_LEN который задефан наверху
    char* password = (char*)calloc(PASSWORD_LEN, sizeof(char));
    char* password2 = (char*)calloc(PASSWORD_LEN, sizeof(char));

    //сбор флагов из аргументов
    for (int i = 0; i < argc; i++) {
        for (int j = 0; j < 3; j++) {
            if (strcmp(argv[i], lmflags[j]) == 0) {
                if (lm) {
                    printf("Submitting two or more of the same flags may result in unforeseen errors!");
                }
                lm = true;
            }
            if (strcmp(argv[i], xsflags[j]) == 0) {
                if (xs) {
                    printf("Submitting two or more of the same flags may result in unforeseen errors!");
                }
                xs = true;
            }
            if (strcmp(argv[i], hflags[j]) == 0) {
                h = true;
            }
            if (strcmp(argv[i], u2pflags[j]) == 0) {
                if (u2p) {
                    printf("Submitting two or more of the same flags may result in unforeseen errors!");
                }
                u2p = true;
            }
            if (strcmp(argv[i], utrflags[j]) == 0) {
                if (utr) {
                    printf("Submitting two or more of the same flags may result in unforeseen errors!");
                }
                utr = true;
            }
            if (strcmp(argv[i], uekflags[j]) == 0) {
                if (uek) {
                    printf("Submitting two or more of the same flags may result in unforeseen errors!");
                }
                uek = true;
                ekpos = i;
            }
            if (strcmp(argv[i], aesflags[j]) == 0) {
                if (aes) {
                    printf("Submitting two or more of the same flags may result in unforeseen errors!");
                }
                aes = true;
            }
            if (strcmp(argv[i], serveflags[j]) == 0) {
                if (serve) {
                    printf("Submitting two or more of the same flags may result in unforeseen errors!");
                }
                serve = true;
            }
        }
    }

    if (h) { //хелп страница
        printf("Usage: %s <input file> <flags>(optional)\n", argv[0]);
        printf("        Flags                             Description                        \n");
        printf(" -lm,    -l, --low-memory | low memory mode                                 |\n");
        printf(" -xs,    -x,    --xs-mode | extended security mode                          |\n");
        printf(" -up,    -u,   --u2p-mode | use second password to generate keys            |\n");
        printf(" -tr,    -t,    --ut-mode | use true random to generate keys                |\n");
        printf(" -ek,    -e,   --uek-mode | <key1 file> <key2 file>(opt) - use external key |\n");
        printf(" -aes,   -a,   --aes-mode | Use aes encryption                              |\n");
        printf(" -hp,    -h,       --help | help                                            |\n");
        printf(" -sv,    -s,      --serve | Run a HTTP server on port 23444                 |\n");
        printf("__________________________|_________________________________________________|\n");
        printf("         Errors           |               Description                       |\n");
        printf(" Segmentation fault       | File not exist/can't alloc mem (not enough RAM) |\n");
        printf(" Memory allocation failed | Not enough RAM to load/init file                |\n");
        printf(" Key generation failed    | Can't allocate memory to load/init key(s)       |\n");
        printf(" Key size mismatch        | Size of file and key file(s) aren't equal       |\n");
        return 0;
    } 

    if (serve) {
        return do_serve();
    }

    bool lack_pos_args = true;
    for (int ai = 1; ai < argc; ++ai) {
        lack_pos_args &= argv[ai][0] == '-';
    }
    if (lack_pos_args) {
        #ifdef __linux__
            printf("\033[91mFile is not specified\n\033[0m");
        #endif
        #ifdef _WIN32
            printf("File is not specified\n");
        #endif
        printf("Usage: %s <input file> <flags>(optional)\n", argv[0]);
        return 0;
    }
    if (aes && u2p) {
        printf("Aes mode doesn't support 2 keys");
        u2p = false;
    }

    if (uek) { //использование внешнего ключа ОБЯЗАТЕЛЬНО должен быть такого же размера как и файл на линуксе если ключ был загенерен -utr то можно считать что криптостойкость равна 100% а на винде не знаю там использована <random> (гугл пишет что random достаточно криптостойкий)
        if (0 - (int)xs - (int)lm - (int)utr < 0) {
            printf("\033[95mUsing other flags except -u2p with -uek doesn't make sense.");
        }
        if (argc > 4 + (int)xs + (int)lm + (int)utr + ((int)u2p * 2)) {
                printf("Did you forgot add flag -u2p to decrypt/encrypt with 2 keys?\n\033[0m");
            }
            else {
                printf("\n\033[0m");
            }
        uekCrypt uek;
         
        if (!u2p) {
            uek.init(argv[1], argv[ekpos + 1]);
            printf("1/4 step\n");
        }
        else {
            uek.init(argv[1], argv[ekpos + 1], argv[ekpos + 2]);
            printf("1/4 step\n");
        }
        uek.crypt();
        printf("2/4 step\n");
        uek.saveFile();
        printf("3/4 step\n");
        uek.wipe();
        printf("4/4 step\n");
        return 0;
    }

    if (!utr) { // красивый ввод пароля 
        #ifdef __linux__ // версия ввода пароля для linux
        initscr();
        noecho();
        printw("%s", "Enter password: ");
        refresh();
        int i = 0;
        char ch;
        while (i < PASSWORD_LEN) {
            ch = getch();
            if (ch != '\n' && ch != '\r') {
                if (ch != KEY_BACKSPACE && ch != 127) {
                    password[i] = ch;
                    printw("*");
                    refresh();
                    i++;
                } else {
                    if (i > 0) {
                        i--;
                        printw("\b \b");
                        refresh();
                    }
                }
            } else {
                password[i] = '\0';
                break;
            }
        }
        printw("\n\r");
        refresh();
        if (u2p) {
            printw("Enter password: ");
            refresh();
            while (i < PASSWORD_LEN) {
            ch = getch();
            if (ch != '\n' && ch != '\r') {
                if (ch != KEY_BACKSPACE && ch != 127) {
                    password2[i] = ch;
                    printw("*");
                    refresh();
                    i++;
                } else {
                    if (i > 0) {
                        i--;
                        printw("\b \b");
                        refresh();
                    }
                }
            } else {
                password2[i] = '\0';
                break;
            }
        }
        }
        refresh();
        endwin();
        #elif defined(_WIN32) // версия ввода пароля для винды
            char ch;
            printf("Enter password: ");
            for (int i = 0; i < PASSWORD_LEN; i++) {
                ch = getch(); // Get character without echoing it to the screen
                if (ch == '\r') {
                    password[i] = '\0';
                    printf("\n");
                    break;
                } else if (ch == 8 || ch == 127) { // Check if backspace
                    if (i > 0) {
                        printf("\b \b"); // Move cursor back, output space, move cursor back again
                        i-=2;
                    }
                } else {
                    password[i] = ch;
                    printf("*");
                }
            }

            if (u2p) {
                printf("Enter password: ");
                for (int i = 0; i < PASSWORD_LEN; i++) {
                ch = getch(); // Get character without echoing it to the screen
                if (ch == '\r') {
                    password2[i] = '\0';
                    printf("\n");
                    break;
                } else if (ch == 8 || ch == 127) { // Check if backspace
                    if (i > 0) {
                        printf("\b \b"); // Move cursor back, output space, move cursor back again
                        i-=2;
                    }
                } else {
                    password2[i] = ch;
                    printf("*");
                }
            }
            }
        #endif
    }

    if (aes) { //вики пишет что aes256 анб используется для TOP SECRET
        printf("Encrypt file or decrypt (e/d): ");
        char u = getchar();
        ByteArray key, plain, out; 
        size_t endSize;
        dFile d;
        std::string fname(argv[1]), spass(password);
        d.Create(fname);
        d.loadFile();
        size_t size = d.getLoadedSize();
        for (int i = 0; i < spass.size(); i++) {
            key.push_back(spass[i]);
        }
        for (size_t i = 0; i < size; i++) {
            plain.push_back(((char*)(d.memFilePtr))[i]);
        }
        Aes256 aes(key);
        if (u == 'e') { 
            endSize = Aes256::encrypt(key, plain, out);
        }
        else {
            endSize = Aes256::decrypt(key, plain, out);
        }
        d.clear();
        FILE *f = fopen(argv[1], "wb");
        for (size_t i = 0; i < endSize; i++) {
            fwrite(&out[i], 1, 1, f);
        }
        fclose(f);
        return 0;
        
    }

    if (!u2p && lm && !xs) {
        #ifdef __linux__
            printf("\033[95mUsing -lm flag without second password doesn't make any sense\n\033[0m");
        #endif
        #ifdef _WIN32
            printf("Using -lm flag without second password doesn't make any sense\n");
        #endif
    }

    if (xs) {
        #ifdef __linux__
            printf("\033[95mUsing -xs can slow down the process 2-5 times\n\033[0m");
        #endif
        #ifdef _WIN32
            printf("Using -xs can slow down the process 2-5 times\n");
        #endif
    }
    //ниже представлены разные типы (по сути только генерации ключа;) 
    //поведения при разных комбинациях флагов)
    if (!lm && !xs) {
        Crypt crypt;
        if (!u2p) {
            if (!utr) {
                #ifdef __linux__
                    printf("\033[91mUsing single key without -xs or -utr very very very unsafe!\n\033[0m"); 
                #endif
                #ifdef _WIN32
                    printf("Using single key without -xs or -utr very very very unsafe!\n");
                #endif
                /*
                Тут по моим расчетом если за скорость шифрования 
                взять 1/4 сек и если файл был БЕЗ сигнатур(т.е. неизвестно ни одного
                байта данного файла) то среднее время взлома около
                33 лет НО если в файле была сигнатура (например в .exe его первые два байта 4D 5A) то 
                время взлома падает до 5 минут т.е. время взлома уменьшается в 
                ~33000000 раз! Это так для справки
                */
            }
            crypt.setThreads(1); // да да МуЛьТиПоТоЧнОсТь или мне лень переписывать
            printf("1/4 step\n");
            crypt.init(argv[1], password, utr);
        }
        else if (u2p) {
            crypt.setThreads(1);
            printf("1/4 step\n");
            crypt.init(argv[1], password, password2, utr);
        }
        cout << t.getAllocSz() << "Mem use" << endl;
        crypt.cryptFile();
        printf("2/4 step\n");
        cout << t.getAllocSz() << "Mem use" << endl;
        crypt.saveFile();
        printf("3/4 step\n");
        cout << t.getAllocSz() << "Mem use" << endl;
        crypt.wipe();
        printf("4/4 step\n");
        cout << t.getAllocSz() << "Mem use" << endl;
        crypt.clear();
        printf("Done\n");
        cout << t.getAllocSz() << "Mem use" << endl;
        return 0;
    }

    if (lm && !xs) {
        #ifdef __linux__
            printf("\033[91mUsing single key without -xs or -utr very very very unsafe!\n\033[0m"); 
        #endif
        #ifdef _WIN32
            printf("Using single key without -xs or -utr very very very unsafe!\n");
        #endif
        lmCrypt lm;
        if (!u2p) {
            lm.init(argv[1], password, utr);
            printf("1/4 step\n");
        }
        if (u2p) {
            lm.amCrypt(argv[1], password, password2, utr);
            printf("%d/%d step\n", 1 + (int)u2p, 3 + (int)u2p);
            lm.saveFile();
            printf("%d/%d step\n", 2 + (int)u2p, 3 + (int)u2p);
            lm.clear();
            printf("%d/%d step\n", 3 + (int)u2p, 3 + (int)u2p);
            printf("Done\n");
            return 0;
        }
        lm.crypt();
        printf("2/4 step\n");
        lm.saveFile();
        printf("3/4 step\n");
        lm.wipe();
        printf("4/4 step\n");
        lm.clear();
        printf("Done\n");
        return 0;
    }

    if (xs && !lm) {
        #ifdef __linux__
            printf("\033[95mFlag -xs is not compatible with flags -lm and -xs\n\033[0m");
        #endif
        #ifdef _WIN32
            printf("Flag -xs is not compatible with flags -lm and -xs aa\n");
        #endif
        xsCrypt xs;
        if (!u2p) {
            xs.init(argv[1], password, utr, 8);
            printf("1/3 step\n");
        }
        if (u2p) {
            xs.init(argv[1], password, password2, utr, 8); //8 не трогать а то все сломается ПОЛНОСТЬЮ!!!
            printf("1/3 step\n");
        }
        xs.crypt();
        printf("2/3 step\n");
        xs.saveFile();
        printf("3/3 step\n");
        xs.wipe();
        printf("Done\n");
        return 0;
    }
    
    if (xs && lm) {
        #ifdef __linux__
            printf("\033[95mFlags -lm with -xs is not compatible with flag -xs\033[0m\n");
        #endif
        #ifdef _WIN32
            printf("Flags -lm with -xs is not compatible with flag -xs\n");
        #endif
        lmxsCrypt lmxs;
        if (!u2p) {
            lmxs.init(argv[1], password, utr);
            printf("1/4 step\n");
            
        }
        else {
            lmxs.init(argv[1], password, password2, utr);
            printf("1/4 step\n");
        }
        lmxs.crypt();
        printf("2/4 step\n");
        lmxs.saveFile();
        printf("3/4 step\n");
        lmxs.wipe();
        printf("4/4 step\n");
        printf("Done\n");
        return 0;
    }
    //idk как сюда можно попасть но ладно
    #ifdef __linux__
        printf("\033[91mYou have reached logic error please send to me (Empers0n) this string: %d%d%d%d%d%d\n\033[0m", (int)lm, (int)xs, (int)u2p, (int)utr, (int)lm, (int)xs);
    #endif 
    #ifdef _WIN32
        printf("You have reached logic error please send to me (Empers0n) this string: %d%d%d%d%d%d\n", (int)lm, (int)xs, (int)u2p, (int)utr, (int)lm, (int)xs);
    #endif
    return 0;
}
