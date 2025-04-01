#include "rsa.h"
#include "num.hpp"
#include "crypt.h"
#include <sstream>


class PrivateKey {
public:
    Num n, d;
};

class PublicKey {
public:
    Num n, e;
};

class RSA {
protected:
    Num encrypt(Num m);
    Num decrypt(Num m);
public:
    PublicKey public_key;
    PrivateKey private_key;
    RSA(PrivateKey private_key, PublicKey public_key) : private_key(private_key), public_key(public_key) {};
    RSA(PublicKey public_key) : public_key(public_key) {};
    RSA(size_t n_bits) {
        tie(this->private_key, this->public_key) = genRandKeys(n_bits);
    };
    tuple<PrivateKey, PublicKey> genRandKeys(size_t n_bits);
    std::string encrypt(const std::string &plaintext);
    std::string decrypt(const std::string &plaintext);
};

bool isPrimeFermat(Num n, int iterc=10) {
    if (n < 4) {
        return n == 2 || n == 3;
    }
    for (int i = 0; i < iterc; ++i) {
        Num base = Num::random_bits(n.bitlength(), genRandBytes);
        if (base.mod_pow(n-1, n) != 1) return false;
    }
    return true;
}

Num genPrime(size_t n_bits) {
    while (true) {
        Num rand_num = Num::random_bits(n_bits, genRandBytes);
        if (isPrimeFermat(rand_num, 40)) {
            return rand_num;
        }
    }
}

Num egcd(Num a, Num b) {
    Num old_r = a, r = b;
    Num old_s = 1, s = 0;
    Num old_t = 0, t = 1;
    while (r != 0) {
        Num q = old_r / r;
        tie(old_r, r) = make_tuple(r, old_r - q*r);
        tie(old_s, s) = make_tuple(s, old_s - q*s);
        tie(old_t, t) = make_tuple(t, old_t - q*t);
    }
    return old_s;
}


tuple<PrivateKey, PublicKey> RSA::genRandKeys(size_t n_bits) {
    Num p = genPrime(n_bits), q = genPrime(n_bits);
    cout << "Gen'd" << endl;
    Num n = p * q;
    Num phi = (p-1) * (q-1);
    Num e = (1 << 16) + 1;
    Num d = (phi + egcd(e, phi)) % phi;
    cout << phi << ' ' << e << ' ' << d << endl;
    return {{.n = n, .d = d}, {.n = n, .e = e}};
}

Num RSA::encrypt(Num m) {
    return m.mod_pow(this->public_key.e, this->public_key.n);
}

Num RSA::decrypt(Num m) {
    return m.mod_pow(this->private_key.d, this->private_key.n);
}

Num string_to_num(const std::string &s) {
    Num result = 0;  // TODO shift only once?
    for (unsigned char c : s) {
        result = (result << 8) + c;
    }
    return result;
}

std::string num_to_string(const Num &n, int base = 256, char offset = 0) {
    std::string s;
    Num k = n;
    while (k != 0) {
        s.push_back(offset + (char) (k % base).to_double());  // There's no Num::to_long()?
        k /= base;
    }
    return s;
}


std::string RSA::encrypt(const std::string &plaintext) {  // TODO FIXME WONT WORK FOR PLAINTEXTS CONTAINING \0!!!! also, totally unsecure 100%
    Num n = public_key.n;
    size_t bs = (n.bitlength() - 1) / 8;
    std::string res;
    for (size_t cp = 0; cp < plaintext.size(); cp += bs) {
        Num m = string_to_num(plaintext.substr(cp, bs));
        m = encrypt(m);
        cout << plaintext.substr(cp, bs) << " encrypted: " << m << endl;
        std::vector<char> out;
        m.print(out);
        if (m[m.size()-1] == '\0') m.pop_back();
        res.append(std::string(out.begin(), out.end()));
        if (cp + bs < plaintext.size()) res.push_back('_');
    }
    return res;
}

std::string RSA::decrypt(const std::string &ciphertext) {
    Num n = private_key.n;
    size_t bs = (n.bitlength() - 1) / 8;
    std::string res;
    std::istringstream stream(ciphertext);
    std::string token;
    while (std::getline(stream, token, '_')) {
        Num m(token.c_str());
        m = decrypt(m);
        cout << token << ' ' << m << endl;
        res.append(num_to_string(m));
    }
    return res;
}


