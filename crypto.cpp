#include "config.h"
#include "crypto.hpp"


void crypto::handle_errors(){
        ERR_print_errors_fp(stderr);
        abort();
}

void crypto::pbkdf2(const std::string& password, std::string& key){
        unsigned char salt[SALT_SIZE];
        if(RAND_bytes(salt, SALT_SIZE) != 1){
            handle_errors();  
        }

        unsigned char derived_key[KEY_SIZE];
        if(PKCS5_PBKDF2_HMAC(password.c_str(), password.size(),
                            salt, SALT_SIZE,
                            ITERATIONS,
                            EVP_sha256(),
                            KEY_SIZE,
                            derived_key) != 1){
            handle_errors();  
        }

        key = std::string((char*)derived_key, KEY_SIZE);
}

void crypto::generate_salt(std::string& salt){
        unsigned char buffer[SALT_SIZE];
        RAND_bytes(buffer, SALT_SIZE);
        salt = std::string((char*)buffer, SALT_SIZE);
}



void crypto::AES::generate_key(std::string& key){
        unsigned char buffer[KEY_SIZE];
        RAND_bytes(buffer, KEY_SIZE);
        key = std::string((char*)buffer, KEY_SIZE);

}

void crypto::AES::generate_iv(std::string& iv){
        unsigned char buffer[IV_SIZE];
        RAND_bytes(buffer, IV_SIZE);
        iv = std::string((char*)buffer, IV_SIZE);
}

void crypto::AES::encrypt(const std::string& input, std::string& output, const std::string& key, const std::string& iv){
        EVP_CIPHER_CTX *ctx;
        int len;
        unsigned char ciphertext[input.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm())];
        unsigned char tag[16];

        if(!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, 
                                    reinterpret_cast<const unsigned char*>(key.data()), 
                                    reinterpret_cast<const unsigned char*>(iv.data())))
            handle_errors();

        if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, 
                                    reinterpret_cast<const unsigned char*>(input.data()), input.size()))
            handle_errors();

        int ciphertext_len = len;

        if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_errors();
        ciphertext_len += len;

        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) handle_errors();

        output = iv + std::string(reinterpret_cast<char*>(ciphertext), ciphertext_len) +
                    std::string(reinterpret_cast<char*>(tag), 16);

        EVP_CIPHER_CTX_free(ctx);
}


void crypto::AES::decrypt(const std::string& input, std::string& output, const std::string& key){
        std::string iv = input.substr(0, IV_SIZE);
        std::string actual_input = input.substr(IV_SIZE, input.size() - IV_SIZE - 16);
        std::string tag_string = input.substr(input.size() - 16);

        EVP_CIPHER_CTX *ctx;
        unsigned char plaintext[actual_input.size()];
        int len;

        if(!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

        if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, 
                                    reinterpret_cast<const unsigned char*>(key.data()), 
                                    reinterpret_cast<const unsigned char*>(iv.data())))
            handle_errors();

        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, 
                                    reinterpret_cast<void*>(const_cast<char*>(tag_string.data()))))
            handle_errors();

        if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, 
                                    reinterpret_cast<const unsigned char*>(actual_input.data()), actual_input.size()))
            handle_errors();

        if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0){
            handle_errors();
            return;
        }
        
        int plaintext_len = len;

        output = std::string(reinterpret_cast<char*>(plaintext), plaintext_len);

        EVP_CIPHER_CTX_free(ctx);
}


void crypto::SHA512::encrypt(const std::string& input, std::string& output){
        unsigned char hash[HASH_SIZE];
        SHA512_CTX sha512;
        SHA512_Init(&sha512);
        SHA512_Update(&sha512, input.c_str(), input.size());
        SHA512_Final(hash, &sha512);
        output = std::string((char*)hash, HASH_SIZE);
}
