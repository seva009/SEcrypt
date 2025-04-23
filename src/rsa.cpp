#include "rsa.hpp"
#include "crypt.h"
#include "num.hpp"
#include "tracealloc.h"
#include <algorithm>
#include <cassert>
#include <sstream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <condition_variable>

RSA::RSA(PrivateKey private_key, PublicKey public_key) : private_key(private_key), public_key(public_key) {};
RSA::RSA(PrivateKey private_key) : private_key(private_key) {};
RSA::RSA(PublicKey public_key) : public_key(public_key) {};

RSA::RSA(size_t n_bits)
{
    tie(this->private_key, this->public_key) = genRandKeys(n_bits);
};

Num prime = 0;
std::atomic<bool> found(false);
std::mutex mtx;
std::condition_variable cv;

bool isPrimeFermat(Num n, int iterc)
{
    if (n < 4)
    {
        return n == 2 || n == 3;
    }
    for (int i = 0; i < iterc; ++i)
    {
        if (found) return false;
        Num base = Num::random_bits(n.bitlength(), genRandBytes);
        if (base.mod_pow(n - 1, n) != 1)
            return false;
    }
    return true;
}

Num genPrimeThread(size_t n_bits)
{
    while (!found)
    {
        Num rand_num = Num::random_bits(n_bits, genRandBytes);
        if (!found && isPrimeFermat(rand_num, 40))
        {
            std::lock_guard<std::mutex> lock(mtx);
            found = true;
            prime = rand_num;
            cv.notify_all();
            return rand_num;
        }
    }
    return 0;
}

Num genPrime(size_t n_bits) {
    found = false;
    int nproc = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;
    for (int i = 0; i < nproc; ++i) {
        threads.emplace_back(genPrimeThread, n_bits);
    }
    std::unique_lock<std::mutex> lock(mtx);
    cv.wait(lock, [] { return found.load(); });
    
    for (auto& t : threads) {
        t.join();
    }
    found = false;
    return prime;
}

Num egcd(Num a, Num b)
{
    Num old_r = a, r = b;
    Num old_s = 1, s = 0;
    Num old_t = 0, t = 1;
    while (r != 0)
    {
        Num q = old_r / r;
        tie(old_r, r) = make_tuple(r, old_r - q * r);
        tie(old_s, s) = make_tuple(s, old_s - q * s);
        tie(old_t, t) = make_tuple(t, old_t - q * t);
    }
    return old_s;
}

tuple<PrivateKey, PublicKey> RSA::genRandKeys(size_t n_bits)
{
    Num p = genPrime(n_bits), q = genPrime(n_bits);
    Num n = p * q;
    Num phi = (p - 1) * (q - 1);
    Num e = (1 << 16) + 1;
    Num d = (phi + egcd(e, phi)) % phi;

    PrivateKey privateKey = {n, d};
    PublicKey publicKey = {n, e};

    return {privateKey, publicKey};
}

Num RSA::encrypt(Num m)
{
    return m.mod_pow(this->public_key.e, this->public_key.n);
}

Num RSA::decrypt(Num m)
{
    return m.mod_pow(this->private_key.d, this->private_key.n);
}

Num string_to_num(const std::string &s)
{
    Num result = 0; // TODO shift only once?
    for (unsigned char c : s)
    {
        result = (result << 8) + c;
    }
    return result;
}

std::string num_to_string(const Num &n, int base, char offset)
{
    std::string s;
    Num k = n;
    while (k != 0)
    {
        s.push_back(offset + (char)(k % base).to_double()); // There's no Num::to_long()?
        k /= base;
    }
    return s;
}

std::string RSA::encrypt(const std::string &plaintext)
{ // TODO FIXME WONT WORK FOR PLAINTEXTS CONTAINING \0!!!! also, totally unsecure 100%
    Num n = public_key.n;
    size_t bs = (n.bitlength() - 1) / 8;
    std::string res;
    for (size_t cp = 0; cp < plaintext.size(); cp += bs)
    {
        Num m = string_to_num(plaintext.substr(cp, bs));
        m = encrypt(m);
        std::vector<char> out;
        m.print(out);
        if (out.back() == '\0')
            out.pop_back();
        res.append(std::string(out.begin(), out.end()));
        if (cp + bs < plaintext.size())
            res.push_back('_');
    }
    return res;
}

std::string RSA::decrypt(const std::string &ciphertext)
{
    Num n = private_key.n;
    size_t bs = (n.bitlength() - 1) / 8;
    std::string res;
    std::istringstream stream(ciphertext);
    std::string token;
    while (std::getline(stream, token, '_'))
    {
        Num m(token.c_str());
        m = decrypt(m);
        std::string out = num_to_string(m);
        std::reverse(out.begin(), out.end());
        res.append(out);
    }
    return res;
}

std::string PublicKey::serialize()
{
    std::string out;
    std::vector<char> tmpout;
    n.print(tmpout);
    if (tmpout.back() == '\0')
        tmpout.pop_back();
    out.append(std::string(tmpout.begin(), tmpout.end()));
    out.push_back('_');
    tmpout.clear();
    e.print(tmpout);
    if (tmpout.back() == '\0')
        tmpout.pop_back();
    out.append(std::string(tmpout.begin(), tmpout.end()));
    return out;
}

PublicKey PublicKey::deserialize(const std::string &s)
{
    std::istringstream stream(s);
    std::string token;
    std::vector<Num> tokens;
    while (std::getline(stream, token, '_'))
    {
        Num m(token.c_str());
        tokens.push_back(m);
    }
    assert(tokens.size() == 2);
    PublicKey publickey = {tokens[0], tokens[1]};
    return publickey;
};

std::string PrivateKey::serialize()
{
    std::string out;
    std::vector<char> tmpout;
    n.print(tmpout);
    if (tmpout.back() == '\0')
        tmpout.pop_back();
    out.append(std::string(tmpout.begin(), tmpout.end()));
    out.push_back('_');
    tmpout.clear();
    d.print(tmpout);
    if (tmpout.back() == '\0')
        tmpout.pop_back();
    out.append(std::string(tmpout.begin(), tmpout.end()));
    return out;
}

PrivateKey PrivateKey::deserialize(const std::string &s)
{
    std::istringstream stream(s);
    std::string token;
    std::vector<Num> tokens;
    while (std::getline(stream, token, '_'))
    {
        Num m(token.c_str());
        tokens.push_back(m);
    }
    assert(tokens.size() == 2);
    PrivateKey privKey{tokens[0], tokens[1]};
    return privKey;
}
