#ifndef CRYPTO_HPP
#define CRYPTO_HPP

#include "config.h"

namespace crypto {

    void handle_errors();

    void pbkdf2(const std::string& password, std::string& key);

    void generate_salt(std::string& salt);

    class AES {
        static const int KEY_SIZE = 32;
        static const int IV_SIZE = 16;
        static const int BLOCK_SIZE = 32;

        void generate_key(std::string& key);

        void generate_iv(std::string& iv);

        void encrypt(const std::string& input, std::string& output, const std::string& key, const std::string& iv);

        void decrypt(const std::string& input, std::string& output, const std::string& key);
    };

    class SHA512 {
        static const int HASH_SIZE = 64;

        void encrypt(const std::string& input, std::string& output);
    };

} // namespace crypto

#endif // CRYPTO_HPP


