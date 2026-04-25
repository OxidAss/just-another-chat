#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <cstring>

static const int IV_LEN  = 12;
static const int TAG_LEN = 16;

std::string derive_key(const std::string& passphrase) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(passphrase.data()),
           passphrase.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

std::string aes_encrypt(const std::string& plaintext, const std::string& key32) {
    if (key32.size() != 32)
        throw std::runtime_error("Key must be 32 bytes");

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::string result;
    result.resize(IV_LEN + TAG_LEN + plaintext.size());

    // Write IV
    std::memcpy(&result[0], iv, IV_LEN);

    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx,
        EVP_aes_256_gcm(), nullptr,
        reinterpret_cast<const unsigned char*>(key32.data()), iv);

    EVP_EncryptUpdate(ctx,
        reinterpret_cast<unsigned char*>(&result[IV_LEN + TAG_LEN]),
        &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        static_cast<int>(plaintext.size()));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx,
        reinterpret_cast<unsigned char*>(&result[IV_LEN + TAG_LEN]) + len,
        &len);
    ciphertext_len += len;

    // Write TAG after IV
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN,
        &result[IV_LEN]);

    EVP_CIPHER_CTX_free(ctx);

    result.resize(IV_LEN + TAG_LEN + ciphertext_len);
    return result;
}

std::string aes_decrypt(const std::string& data, const std::string& key32) {
    if (key32.size() != 32)
        throw std::runtime_error("Key must be 32 bytes");
    if (static_cast<int>(data.size()) < IV_LEN + TAG_LEN)
        throw std::runtime_error("Data too short");

    const unsigned char* iv  = reinterpret_cast<const unsigned char*>(&data[0]);
    unsigned char tag[TAG_LEN];
    std::memcpy(tag, &data[IV_LEN], TAG_LEN);

    const unsigned char* ciphertext =
        reinterpret_cast<const unsigned char*>(&data[IV_LEN + TAG_LEN]);
    int ciphertext_len = static_cast<int>(data.size()) - IV_LEN - TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::string plaintext(ciphertext_len, '\0');
    int len = 0, plaintext_len = 0;

    EVP_DecryptInit_ex(ctx,
        EVP_aes_256_gcm(), nullptr,
        reinterpret_cast<const unsigned char*>(key32.data()), iv);

    EVP_DecryptUpdate(ctx,
        reinterpret_cast<unsigned char*>(&plaintext[0]),
        &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);

    int ret = EVP_DecryptFinal_ex(ctx,
        reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0)
        throw std::runtime_error("AES-GCM auth tag mismatch — message tampered");

    plaintext_len += len;
    plaintext.resize(plaintext_len);
    return plaintext;
}