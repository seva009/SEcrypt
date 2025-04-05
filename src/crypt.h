#ifndef CRYPT_H
#define CRYPT_H

#include <string>
#include <random>

using namespace std;

class Crypt {
protected:
    mt19937_64 gen1, gen2;
    size_t size = 0;
    dFile file;
    bool hasNd = false;
    void* memKey;
    void* ndMemKey;
    int threads;
    bool utr = false;

    void* genKey(unsigned int seed, size_t size, mt19937_64& eng);
    unsigned int htoui(const std::string& md5hash);
    unsigned int MD5HashToUInt(const std::string& str);
public:
    void init(std::string filename, std::string password, std::string ndPassword, bool utr = false);
    void init(std::string filename, std::string password, bool utr = false);
    void* crypt(void* key1, void* key2, void* file, unsigned long len, int usp, int threads);
    void cryptFile();
    void saveFile();
    void setThreads(int numThreads);
    void wipe();
    void clear();
};

class xsCrypt : public Crypt {
protected:
    void* keys[16];
    int kc = 0;
public:
    void init(string filename, string password, string ndPassword, bool utr = false, int spl = 8);
    void init(string filename, string password, bool utr = false, int spl = 8);
    void crypt();
    void wipe();
};

class lmCrypt : public Crypt {
protected:
    void* keys[2];
public:
    void init(string filename, string password, bool utr = false);
    void amCrypt(string filename, string password, string ndPassword, bool utr = false);
    void crypt();
    void wipe();
};

class lmxsCrypt : public Crypt {
protected:
    void* keys[2];
    void modKey(unsigned int seed, size_t size, mt19937_64& eng, void* key);
    void sModKey(void* key, size_t size);
    void sModKey(void* key, size_t size, mt19937_64& eng);
public:
    void init(string filename, string password, bool utr = false);
    void init(string filename, string password, string ndPassword, bool utr = false);
    void crypt();
    void wipe();
};

class uekCrypt {
private:
    dFile file, key, key2;
    size_t size, kSize, kSize2;
    bool hasNd;
public:
    void init(string filename, string keyname);
    void init(string filename, string keyname, string ndKeyname);
    void crypt();
    void saveFile();
    void wipe();
};

#endif // CRYPT_H
