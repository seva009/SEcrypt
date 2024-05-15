#include <iostream>
#include "md5.h"
#include <random>
#include <stdio.h>
#include <string.h>
#include "dFile.h"
#include <string>
#include <cstdlib>


using namespace std;

#ifndef __WIN__
    #ifndef __LINUX__
        #error Platform not selected please add flag -D__LINUX__ or -D__WIN__
    #endif
#endif

#ifdef __LINUX__
    #ifdef __WIN__
        #error Only one platform can be selected please remove one of the flags -D__LINUX__ or -D__WIN__
    #endif
#endif

#ifdef __WIN__
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

#ifdef __LINUX__
void* sGenKey(size_t size) {
    FILE *fileF = fopen("/dev/random", "rb");
    void* memKey = malloc(size);
    if (memKey == nullptr) {
        return nullptr;
    }
    fread(memKey, size, 1, fileF);
    fclose(fileF);
    return memKey;
}
#endif

class Crypt {
    private:
    mt19937_64 gen1, gen2;
    size_t size = 0;
    dFile file;
    bool hasNd = false;
    void* memKey;
    void* ndMemKey;
    int threads;
    bool utr = false;
        void* genKey(unsigned int seed, size_t size, mt19937_64& eng) {
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

        unsigned int htoui(const std::string& md5hash) {
            std::string subHash = md5hash.substr(0, 8);
            unsigned int result = std::stoul(subHash, nullptr, 16);

            return result;
        }

        unsigned int MD5HashToUInt(const std::string& str) {
            std::string hashStr = md5(str);
            unsigned int result = htoui(hashStr);

            return result;
        }
    public:
        void init(string filename, string password, string ndPassword, bool utr = false) {
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
                #ifdef __WIN__
                    memKey = sGenKey(size, gen1);
                    ndMemKey = sGenKey(size, gen2);
                #endif
                #ifdef __LINUX__
                    memKey = sGenKey(size);
                    ndMemKey = sGenKey(size);
                #endif
            }
            else{
                memKey = genKey(hash, size, gen1);
                ndMemKey = genKey(ndHash, size, gen2);
            }
            if (memKey == nullptr || ndMemKey == nullptr) {
                throw std::runtime_error("Key generation failed");
            }
        }

        void init(string filename, string password, bool utr = false) {
            this->utr = utr;
            file.Create(filename);
            file.loadFile();
            size = file.getLoadedSize();
            unsigned int hash = MD5HashToUInt(password);
            if (utr) {
                #ifdef __WIN__
                    memKey = sGenKey(size, gen1);
                #endif
                #ifdef __LINUX__
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

        void* crypt(void *key1, void *key2, void *file, unsigned long len, int usp, int threads) {
            void *out = file;
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

        void cryptFile() {
            if (hasNd) {
                file.memFilePtr = crypt(memKey, ndMemKey, file.memFilePtr, size, 1, threads);
            }
            else {
                file.memFilePtr = crypt(memKey, memKey, file.memFilePtr, size, 0, threads);
            }
        }

        void saveFile() {
            FILE *fileF = fopen(file.filename, "wb");
            fwrite(file.memFilePtr, size, 1, fileF);
            fclose(fileF);
        }

        void setThreads(int numThreads) {
            threads = numThreads;
        }

        void wipe() {
            if (utr) {
                FILE *fileF = fopen("key1", "wb");
                fwrite(memKey, size, 1, fileF);
                fclose(fileF);
            }
            memset(memKey, 0, size);
            free(memKey);
            if (hasNd) {
                if (utr) {
                    FILE *fileF2 = fopen("key2", "wb");
                    fwrite(ndMemKey, size, 1, fileF2);
                    fclose(fileF2);
                }
                memset(ndMemKey, 0, size);
                free(ndMemKey);
            }
            
        }
        void clear() {
            file.clear();
        }
};

class xsCrypt {
    private:
        dFile file;
        size_t size = 0;
        bool hasNd = false;
        void* keys[16];
        int kc = 0;
        bool utr;
        mt19937_64 gen1, gen2;
        void* genKey(unsigned int seed, size_t size, mt19937_64& eng) {
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

        unsigned int htoui(const std::string& md5hash) {
            std::string subHash = md5hash.substr(0, 8);
            unsigned int result = std::stoul(subHash, nullptr, 16);

            return result;
        }

        unsigned int MD5HashToUInt(const std::string& str) {
            std::string hashStr = md5(str);
            unsigned int result = htoui(hashStr);

            return result;
        }
    public:
        void init(string filename, string password, string ndPassword, bool utr = false, int spl = 8) {
            this->utr = utr;
            hasNd = true;
            string hashStr, hashStr2;
            file.Create(filename);
            file.loadFile();
            size = file.getLoadedSize();
            if (utr) {
                #ifdef __WIN__
                    for (int i = 0; i < 4; i++) {
                        keys[i] = sGenKey(size, gen1);
                    }
                    for (int i = 0; i < 4; i++) {
                        keys[i + 4] = sGenKey(size, gen2);
                    }
                #endif
                #ifdef __LINUX__
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

        void crypt() {
            for (size_t i = 0; i < size; i++) {
                for (int j = 0; j < kc; j++) {
                    ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[j])[i];
                }
            }
        }

        void saveFile() {
            FILE *fileF = fopen(file.filename, "wb");
            fwrite(file.memFilePtr, size, 1, fileF);
            fclose(fileF);
        }

        void wipe() {
            char* filename = (char*)calloc(256, sizeof(char));
            for (int j = 0; j < kc; j++) {
                if (utr) {
                    snprintf(filename, 9, "key%d", j);
                    FILE *fileF = fopen(filename, "wb");
                    fwrite(keys[j], size, 1, fileF);
                    fclose(fileF);
                }
                memset(keys[j], 0, size);
                free(keys[j]);
            }
            file.clear();
        }

        void init(string filename, string password, bool utr = false, int spl = 8) {
            string hashStr;
            file.Create(filename);
            file.loadFile();
            size = file.getLoadedSize();
            if (utr) {
                #ifdef __WIN__
                    for (int i = 0; i < 4; i++) {
                        keys[i] = sGenKey(size, gen1);
                    }
                #endif
                #ifdef __LINUX__
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
};

class lmCrypt {
    private:
        mt19937_64 gen1, gen2;
        size_t size = 0;
        void* keys[2];
        dFile file;
        bool utr;
        void* genKey(unsigned int seed, size_t size, mt19937_64& eng) {
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

    public:
        void init(string filename, string password, bool utr = false) {
            this->utr = utr;
            file.Create(filename);
            file.loadFile();
            size = file.getLoadedSize();
            if (utr) {
                #ifdef __WIN__
                    keys[0] = sGenKey(size, gen1);
                #endif
                #ifdef __LINUX__
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

        void amCrypt(string filename, string password, string ndPassword, bool utr = false) {
            this->utr = utr;
            file.Create(filename);
            file.loadFile();
            size = file.getLoadedSize();
            if (utr) {
                #ifdef __WIN__
                    keys[0] = sGenKey(size, gen1);
                #endif
                #ifdef __LINUX__
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
                FILE *fileF = fopen("key1", "wb");
                fwrite(keys[0], size, 1, fileF);
                fclose(fileF);
            }
            memset(keys[0], 0, size);
            free(keys[0]);
            if (utr) {
                #ifdef __WIN__
                    keys[0] = sGenKey(size, gen2);
                #endif
                #ifdef __LINUX__
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
                FILE *fileF2 = fopen("key2", "wb");
                fwrite(keys[0], size, 1, fileF2);
                fclose(fileF2);
            }
            memset(keys[0], 0, size);
            free(keys[0]);
        }

        void crypt() {
            for (size_t i = 0; i < size; i++) {
                ((unsigned char*)file.memFilePtr)[i] ^= ((unsigned char*)keys[0])[i];
            }
        }

        void saveFile() {
            FILE *fileF = fopen(file.filename, "wb");
            fwrite(file.memFilePtr, size, 1, fileF);
            fclose(fileF);
        }

        void wipe() {
            if (utr) {
                FILE *fileF = fopen("key1", "wb");
                fwrite(keys[0], size, 1, fileF);
                fclose(fileF);
            }
            memset(keys[0], 0, size);
            free(keys[0]);
        }

        void clear() {
            file.clear();
        }
};

class lmxsCrypt {
    private:
        mt19937_64 gen1, gen2;
        size_t size = 0;
        void* keys[2];
        dFile file;
        bool hasNd = false;
        bool utr;
        void* genKey(unsigned int seed, size_t size, mt19937_64& eng) {
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
        void modKey(unsigned int seed, size_t size, mt19937_64& eng, void* key) {
            eng.seed(seed);
            for (size_t i = 0; i < size; i++) {
                ((unsigned char*)key)[i] ^= eng() % (unsigned char)-1;
            }
        }
        #ifdef __WIN__
            void sModKey(void* key, size_t size, mt19937_64& eng) {
                std::random_device rd;
                eng.seed(rd());
                std::uniform_int_distribution<> dis(1, (unsigned char)-1);
                for (size_t i = 0; i < size; i++) {
                    ((unsigned char*)key)[i] ^= dis(eng) % (unsigned char)-1;
                }
            }
        #endif
        #ifdef __LINUX__
            void sModKey(void* key, size_t size) {
                FILE *fileF = fopen("/dev/random", "rb");
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
    public:
        void init(string filename, string password, bool utr = false) {
            this->utr = utr;
            file.Create(filename);
            file.loadFile();
            size = file.getLoadedSize();
            if (utr) {
                #ifdef __WIN__
                    keys[0] = sGenKey(size, gen1);
                #endif
                #ifdef __LINUX__
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
                    #ifdef __WIN__
                        sModKey(keys[0], size, gen1);
                    #endif
                    #ifdef __LINUX__
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
        void init(string filename, string password, string ndPassword, bool utr = false) {
            file.Create(filename);
            hasNd = true;
            file.loadFile();
            size = file.getLoadedSize();
            if (utr) {
                #ifdef __WIN__
                    keys[0] = sGenKey(size, gen1);
                    keys[1] = sGenKey(size, gen2);
                #endif
                #ifdef __LINUX__
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
                    #ifdef __WIN__
                        sModKey(keys[0], size, gen1);
                        sModKey(keys[1], size, gen2);
                    #endif
                    #ifdef __LINUX__
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

        void crypt() {
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

        void saveFile() {
            FILE *fileF = fopen(file.filename, "wb");
            fwrite(file.memFilePtr, size, 1, fileF);
            fclose(fileF);
        }

        void wipe() {
            if (!hasNd) {
                if (utr) {
                    FILE *fileF = fopen("key1", "wb");
                    fwrite(keys[0], size, 1, fileF);
                    fclose(fileF);
                }
                memset(keys[0], 0, size);
                free(keys[0]);
            }
            else {
                if (utr) {
                    FILE *fileF = fopen("key1", "wb");
                    fwrite(keys[0], size, 1, fileF);
                    fclose(fileF);
                }
                memset(keys[0], 0, size);
                free(keys[0]);
                FILE *fileF2 = fopen("key2", "wb");
                fwrite(keys[1], size, 1, fileF2);
                fclose(fileF2);
                memset(keys[1], 0, size);
                free(keys[1]);
            }
        }
};

class uekCrypt {
    private:
        dFile file, key, key2;
        size_t size, kSize, kSize2;
        bool hasNd;
    public:
        void init(string filename, string keyname) {
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

        void init(string filename, string keyname, string ndKeyname) {
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

        void crypt() {
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

        void saveFile() {
            FILE *fileF = fopen(file.filename, "wb");
            fwrite(file.memFilePtr, size, 1, fileF);
            fclose(fileF);
        }

        void wipe() {
            file.clear();
            key.clear();
            key2.clear();
        }
};