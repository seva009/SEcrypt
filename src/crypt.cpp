#include "tracealloc.h"
#include <iostream>
#include "md5.h"
#include <random>
#include <stdio.h>
#include <string.h>
#include "dFile.h"
#include <string>
#include <cstdlib>
#include "crypt.h"


using namespace std;

#ifndef _WIN32
#ifndef __linux__
#error Platform not selected please add flag -D__linux__ or -D_WIN32
#endif
#endif

#ifdef __linux__
#ifdef _WIN32
#error Only one platform can be selected please remove one of the flags -D__linux__ or -D_WIN32
#endif
#endif

#ifdef _WIN32
void* sGenKey(size_t size, mt19937_64& eng) {
    void* memKey = malloc(size);
    if (memKey == nullptr) {
        return nullptr;
    }
    std::random_device rd;
    eng.seed(rd());
    std::uniform_int_distribution<> dis(1, (unsigned char)-1);
    for (size_t i = 0; i < size; i++) {
        ((unsigned char*)memKey)[i] = dis(eng) % (unsigned char)-1;
    }
    return memKey;
}
#endif

#ifdef __linux__
void* sGenKey(size_t size) {
    FILE* fileF = fopen("/dev/random", "rb");
    void* memKey = malloc(size);
    if (memKey == nullptr) {
        return nullptr;
    }
    fread(memKey, size, 1, fileF);
    fclose(fileF);
    return memKey;
}
#endif

    void* Crypt::genKey(unsigned int seed, size_t size, mt19937_64& eng) {
        void* memKey = malloc(size);
        if (memKey == nullptr) {
            return nullptr;
        }
        eng.seed(seed);
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)memKey)[i] = eng() % (unsigned char)-1;
        }
        return memKey;
    }

    unsigned int Crypt::htoui(const std::string& md5hash) {
        std::string subHash = md5hash.substr(0, 8);
        unsigned int result = std::stoul(subHash, nullptr, 16);

        return result;
    }

    unsigned int Crypt::MD5HashToUInt(const std::string& str) {
        std::string hashStr = md5(str);
        unsigned int result = htoui(hashStr);

        return result;
    }

    void Crypt::init(string filename, string password, string ndPassword, bool utr) {
        this->utr = utr;
        hasNd = true;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        unsigned int hash = MD5HashToUInt(password);
        unsigned int ndHash = MD5HashToUInt(ndPassword);
        if (hash == ndHash && !utr) {
            throw std::runtime_error("Checksums are same please change one of passwords");
        }
        if (utr) {
#ifdef _WIN32
            memKey = sGenKey(size, gen1);
            ndMemKey = sGenKey(size, gen2);
#endif
#ifdef __linux__
            memKey = sGenKey(size);
            ndMemKey = sGenKey(size);
#endif
        }
        else {
            memKey = genKey(hash, size, gen1);
            ndMemKey = genKey(ndHash, size, gen2);
        }
        if (memKey == nullptr || ndMemKey == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
    }

    void Crypt::init(string filename, string password, bool utr) {
        this->utr = utr;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        unsigned int hash = MD5HashToUInt(password);
        if (utr) {
#ifdef _WIN32
            memKey = sGenKey(size, gen1);
#endif
#ifdef __linux__
            memKey = sGenKey(size);
#endif
        }
        else {
            memKey = genKey(hash, size, gen1);
        }
        if (memKey == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
    }

    void* Crypt::crypt(void* key1, void* key2, void* file, unsigned long len, int usp, int threads) {
        void* out = file;
        if (usp >= 1) {
            for (unsigned long i = 0; i < len; i++) {
                ((unsigned char*)out)[i] ^= ((unsigned char*)key1)[i];
                ((unsigned char*)out)[i] ^= ((unsigned char*)key2)[i];
            }
        }
        else {
            for (unsigned long i = 0; i < len; i++) {
                ((unsigned char*)out)[i] ^= ((unsigned char*)key1)[i];
            }
        }
        return out;
    }

    void Crypt::cryptFile() {
        if (hasNd) {
            file.memFilePtr = crypt(memKey, ndMemKey, file.memFilePtr, size, 1, threads);
        }
        else {
            file.memFilePtr = crypt(memKey, memKey, file.memFilePtr, size, 0, threads);
        }
    }

    void Crypt::saveFile() {
        FILE* fileF = fopen(file.filename, "wb");
        fwrite(file.memFilePtr, size, 1, fileF);
        fclose(fileF);
    }

    void Crypt::setThreads(int numThreads) {
        threads = numThreads;
    }

    void Crypt::wipe() {
        if (utr) {
            FILE* fileF = fopen("key1", "wb");
            fwrite(memKey, size, 1, fileF);
            fclose(fileF);
        }
        memset(memKey, 0, size);
        free(memKey);
        if (hasNd) {
            if (utr) {
                FILE* fileF2 = fopen("key2", "wb");
                fwrite(ndMemKey, size, 1, fileF2);
                fclose(fileF2);
            }
            memset(ndMemKey, 0, size);
            free(ndMemKey);
        }

    }

    void Crypt::clear() {
        file.clear();
    }

    

    void xsCrypt::init(string filename, string password, string ndPassword, bool utr, int spl) {
        this->utr = utr;
        hasNd = true;
        string hashStr, hashStr2;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        if (utr) {
#ifdef _WIN32
            for (int i = 0; i < 4; i++) {
                keys[i] = sGenKey(size, gen1);
            }
            for (int i = 0; i < 4; i++) {
                keys[i + 4] = sGenKey(size, gen2);
            }
#endif
#ifdef __linux__
            for (int i = 0; i < 4; i++) {
                keys[i] = sGenKey(size);
            }
            for (int i = 0; i < 4; i++) {
                keys[i + 4] = sGenKey(size);
            }
#endif
        }
        else {
            hashStr = md5(password);
            hashStr2 = md5(ndPassword);
            for (int i = 0; i < 4; i++) {
                keys[i] = genKey(stoul(hashStr.substr(i * 8, (i + 1) * 8), nullptr, 16), size, gen1);
                if (keys[i] == nullptr) {
                    throw std::runtime_error("Key generation failed");
                }
            }
            for (int i = 0; i < 4; i++) {
                keys[i + 4] = genKey(stoul(hashStr2.substr(i * 8, (i + 1) * 8), nullptr, 16), size, gen1);
                if (keys[i + 4] == nullptr) {
                    throw std::runtime_error("Key generation failed");
                }
            }
        }

        kc = 8;
    }

    void xsCrypt::crypt() {
        for (size_t i = 0; i < size; i++) {
            for (int j = 0; j < kc; j++) {
                ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[j])[i];
            }
        }
    }

    void xsCrypt::wipe() {
        char* filename = (char*)calloc(256, sizeof(char));
        for (int j = 0; j < kc; j++) {
            if (utr) {
                snprintf(filename, 9, "key%d", j);
                FILE* fileF = fopen(filename, "wb");
                fwrite(keys[j], size, 1, fileF);
                fclose(fileF);
            }
            memset(keys[j], 0, size);
            free(keys[j]);
        }
        file.clear();
    }

    void xsCrypt::init(string filename, string password, bool utr, int spl) {
        string hashStr;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        if (utr) {
#ifdef _WIN32
            for (int i = 0; i < 4; i++) {
                keys[i] = sGenKey(size, gen1);
            }
#endif
#ifdef __linux__
            for (int i = 0; i < 4; i++) {
                keys[i] = sGenKey(size);
            }
#endif
        }
        else {
            hashStr = md5(password);
            for (int i = 0; i < 4; i++) {
                unsigned long sd;
                cout << hashStr << endl;
                if (hashStr.length() < (i + 1) * 8) {
                    cout << "Error!!" << endl;
                }
                else {
                    sd = stoul(hashStr.substr(i * 8, 8), nullptr, 16);
                }
                keys[i] = genKey(sd, size, gen1);
                if (keys[i] == nullptr) {
                    throw std::runtime_error("Key generation failed");
                }
            }
        }
        kc = 4;
    }



    void lmCrypt::init(string filename, string password, bool utr) {
        this->utr = utr;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        if (utr) {
#ifdef _WIN32
            keys[0] = sGenKey(size, gen1);
#endif
#ifdef __linux__
            keys[0] = sGenKey(size);
#endif
        }
        else {

            keys[0] = genKey(stoul(md5(password).substr(0, 8), nullptr, 16), size, gen1);
        }
        if (keys[0] == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
    }

    void lmCrypt::amCrypt(string filename, string password, string ndPassword, bool utr) {
        this->utr = utr;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        if (utr) {
#ifdef _WIN32
            keys[0] = sGenKey(size, gen1);
#endif
#ifdef __linux__
            keys[0] = sGenKey(size);
#endif
        }
        else {

            keys[0] = genKey(stoul(md5(password).substr(0, 8), nullptr, 16), size, gen1);
        }
        if (keys[0] == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[0])[i];
        }
        if (utr) {
            FILE* fileF = fopen("key1", "wb");
            fwrite(keys[0], size, 1, fileF);
            fclose(fileF);
        }
        memset(keys[0], 0, size);
        free(keys[0]);
        if (utr) {
#ifdef _WIN32
            keys[0] = sGenKey(size, gen2);
#endif
#ifdef __linux__
            keys[0] = sGenKey(size);
#endif
        }
        else {
            keys[0] = genKey(stoul(md5(ndPassword).substr(0, 8), nullptr, 16), size, gen2);
        }
        if (keys[0] == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[0])[i];
        }
        if (utr) {
            FILE* fileF2 = fopen("key2", "wb");
            fwrite(keys[0], size, 1, fileF2);
            fclose(fileF2);
        }
        memset(keys[0], 0, size);
        free(keys[0]);
    }

    void lmCrypt::crypt() {
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[0])[i];
        }
    }

    void lmCrypt::wipe() {
        if (utr) {
            FILE* fileF = fopen("key1", "wb");
            fwrite(keys[0], size, 1, fileF);
            fclose(fileF);
        }
        memset(keys[0], 0, size);
        free(keys[0]);
    }



    void lmxsCrypt::modKey(unsigned int seed, size_t size, mt19937_64& eng, void* key) {
        eng.seed(seed);
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)key)[i] ^= eng() % (unsigned char)-1;
        }
    }
#ifdef _WIN32
    void lmxsCrypt::sModKey(void* key, size_t size, mt19937_64& eng) {
        std::random_device rd;
        eng.seed(rd());
        std::uniform_int_distribution<> dis(1, (unsigned char)-1);
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)key)[i] ^= dis(eng) % (unsigned char)-1;
        }
    }
#endif
#ifdef __linux__
    void lmxsCrypt::sModKey(void* key, size_t size) {
        FILE* fileF = fopen("/dev/random", "rb");
        void* skey = malloc(size);
        if (skey == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
        fread(skey, size, 1, fileF);
        for (size_t i = 0; i < size; i++) {
            ((unsigned char*)key)[i] ^= ((unsigned char*)skey)[i];
        }
        fclose(fileF);
        memset(skey, 0, size);
        free(skey);
    }
#endif
    void lmxsCrypt::init(string filename, string password, bool utr) {
        this->utr = utr;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        if (utr) {
#ifdef _WIN32
            keys[0] = sGenKey(size, gen1);
#endif
#ifdef __linux__
            keys[0] = sGenKey(size);
#endif
        }
        else {
            keys[0] = genKey(stoul(md5(password).substr(0, 8), nullptr, 16), size, gen1);
        }
        if (keys[0] == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
        if (utr) {
            for (int i = 0; i < 4; i++) {
#ifdef _WIN32
                sModKey(keys[0], size, gen1);
#endif
#ifdef __linux__
                sModKey(keys[0], size);
#endif
                if (keys[i] == nullptr) {
                    throw std::runtime_error("Key generation failed");
                }
            }
        }
        else {
            for (int i = 0; i < 4; i++) {
                modKey(stoul(md5(password).substr(i * 8, (i + 1) * 8), nullptr, 16), size, gen1, keys[0]);
                // if (keys[i] == nullptr) {
                //     throw std::runtime_error("Key modification failed");
                // }
            }
        }
    }
    void lmxsCrypt::init(string filename, string password, string ndPassword, bool utr) {
        file.Create(filename);
        hasNd = true;
        file.loadFile();
        size = file.getLoadedSize();
        if (utr) {
#ifdef _WIN32
            keys[0] = sGenKey(size, gen1);
            keys[1] = sGenKey(size, gen2);
#endif
#ifdef __linux__
            keys[0] = sGenKey(size);
            keys[1] = sGenKey(size);
#endif
        }
        else {
            keys[0] = genKey(stoul(md5(password).substr(0, 8), nullptr, 16), size, gen1);
            keys[1] = genKey(stoul(md5(ndPassword).substr(0, 8), nullptr, 16), size, gen2);
        }
        if (keys[0] == nullptr || keys[1] == nullptr) {
            throw std::runtime_error("Key generation failed");
        }
        if (utr) {
            for (int i = 0; i < 4; i++) {
#ifdef _WIN32
                sModKey(keys[0], size, gen1);
                sModKey(keys[1], size, gen2);
#endif
#ifdef __linux__
                sModKey(keys[0], size);
                sModKey(keys[1], size);
#endif
                if (keys[0] == nullptr || keys[1] == nullptr) {
                    throw std::runtime_error("Key generation failed");
                }
            }
        }
        else {
            for (int i = 0; i < 4; i++) {
                modKey(stoul(md5(password).substr(i * 8, (i + 1) * 8), nullptr, 16), size, gen1, keys[0]);
                modKey(stoul(md5(ndPassword).substr(i * 8, (i + 1) * 8), nullptr, 16), size, gen2, keys[1]);
                if (keys[0] == nullptr || keys[1] == nullptr) {
                    throw std::runtime_error("Key generation failed");
                }
            }
        }
    }

    void lmxsCrypt::crypt() {
        if (hasNd) {
            for (size_t i = 0; i < size; i++) {
                ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[0])[i] ^ ((unsigned char*)keys[1])[i];
            }
        }
        else {
            for (size_t i = 0; i < size; i++) {
                ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[0])[i];
            }
        }

    }

    void lmxsCrypt::wipe() {
        if (!hasNd) {
            if (utr) {
                FILE* fileF = fopen("key1", "wb");
                fwrite(keys[0], size, 1, fileF);
                fclose(fileF);
            }
            memset(keys[0], 0, size);
            free(keys[0]);
        }
        else {
            if (utr) {
                FILE* fileF = fopen("key1", "wb");
                fwrite(keys[0], size, 1, fileF);
                fclose(fileF);
            }
            memset(keys[0], 0, size);
            free(keys[0]);
            FILE* fileF2 = fopen("key2", "wb");
            fwrite(keys[1], size, 1, fileF2);
            fclose(fileF2);
            memset(keys[1], 0, size);
            free(keys[1]);
        }
    }


    void uekCrypt::init(string filename, string keyname) {
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        key.Create(keyname);
        key.loadFile();
        kSize = key.getLoadedSize();
        if (kSize != size) {
            throw std::runtime_error("Key size mismatch");
        }
    }

    void uekCrypt::init(string filename, string keyname, string ndKeyname) {
        hasNd = true;
        file.Create(filename);
        file.loadFile();
        size = file.getLoadedSize();
        key.Create(keyname);
        key.loadFile();
        kSize = key.getLoadedSize();
        key2.Create(ndKeyname);
        key2.loadFile();
        kSize2 = key2.getLoadedSize();
        if (!(kSize < size && kSize2 < size)) {
            throw std::runtime_error("Key size mismatch");
        }
    }

    void uekCrypt::crypt() {
        if (hasNd) {
            for (size_t i = 0; i < size; i++) {
                ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)key.memFilePtr)[i] ^ ((unsigned char*)key2.memFilePtr)[i];
            }
        }
        else {
            for (size_t i = 0; i < size; i++) {
                ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)key.memFilePtr)[i];
            }
        }
    }

    void uekCrypt::saveFile() {
        FILE* fileF = fopen(file.filename, "wb");
        fwrite(file.memFilePtr, size, 1, fileF);
        fclose(fileF);
    }

    void uekCrypt::wipe() {
        file.clear();
        key.clear();
        key2.clear();
    }
