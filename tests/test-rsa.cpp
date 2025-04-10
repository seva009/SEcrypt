#include <cassert>
#include <rsa.hpp>
#include <iostream>

int main(void) {
    RSA rsa(128);
    std::string plain = "This is plaintext";
    assert(plain == rsa.decrypt(rsa.encrypt(plain)));

    std::cout << "RSA passed tests successfully" << std::endl;
}
