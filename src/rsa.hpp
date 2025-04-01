#ifndef RSA_HPP
#define RSA_HPP

#include <string>
#include <tuple>
#include "num.hpp"

class PrivateKey {
public:
    Num n;
    Num d;
    std::string serialize();
    static PrivateKey deserialize(const std::string &);
};

class PublicKey {
public:
    Num n;
    Num e;
    std::string serialize();
    static PublicKey deserialize(const std::string &);
};

class RSA {
protected:
    Num encrypt(Num m);
    Num decrypt(Num m);
public:
    PublicKey public_key;
    PrivateKey private_key;

    RSA(PrivateKey private_key, PublicKey public_key);
    RSA(PrivateKey private_key);
    RSA(PublicKey public_key);
    RSA(size_t n_bits);
    std::tuple<PrivateKey, PublicKey> genRandKeys(size_t n_bits);
    std::string encrypt(const std::string &plaintext);
    std::string decrypt(const std::string &ciphertext);
};

Num string_to_num(const std::string &s);
std::string num_to_string(const Num &n, int base = 256, char offset = 0);
bool isPrimeFermat(Num n, int iterc = 10);
Num genPrime(size_t n_bits);
Num egcd(Num a, Num b);

#endif // RSA_HPP

