#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

static constexpr int IV_LEN      = 12;
static constexpr int TAG_LEN     = 16;
static constexpr int PBKDF2_ITER = 100000;

std::string random_bytes(size_t n) {
    std::string out(n, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&out[0]), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    return out;
}

std::string derive_key(const std::string& passphrase, const std::string& salt) {
    static const std::string default_salt = "jschat-v1-salt-2025";
    const std::string& s = salt.empty() ? default_salt : salt;

    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(
            passphrase.data(), static_cast<int>(passphrase.size()),
            reinterpret_cast<const unsigned char*>(s.data()), static_cast<int>(s.size()),
            PBKDF2_ITER, EVP_sha256(), 32, key) != 1)
        throw std::runtime_error("PBKDF2 failed");

    return std::string(reinterpret_cast<char*>(key), 32);
}

std::string aes_encrypt(const std::string& plaintext, const std::string& key32) {
    if (key32.size() != 32) throw std::runtime_error("Key must be 32 bytes");

    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) throw std::runtime_error("RAND_bytes failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::string result(IV_LEN + TAG_LEN + plaintext.size(), '\0');
    std::memcpy(&result[0], iv, IV_LEN);

    int len = 0, ct_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
        reinterpret_cast<const unsigned char*>(key32.data()), iv);
    EVP_EncryptUpdate(ctx,
        reinterpret_cast<unsigned char*>(&result[IV_LEN + TAG_LEN]), &len,
        reinterpret_cast<const unsigned char*>(plaintext.data()),
        static_cast<int>(plaintext.size()));
    ct_len = len;
    EVP_EncryptFinal_ex(ctx,
        reinterpret_cast<unsigned char*>(&result[IV_LEN + TAG_LEN]) + len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, &result[IV_LEN]);
    EVP_CIPHER_CTX_free(ctx);

    result.resize(IV_LEN + TAG_LEN + ct_len);
    return result;
}

std::string aes_decrypt(const std::string& data, const std::string& key32) {
    if (key32.size() != 32) throw std::runtime_error("Key must be 32 bytes");
    if (static_cast<int>(data.size()) < IV_LEN + TAG_LEN)
        throw std::runtime_error("Data too short");

    const unsigned char* iv = reinterpret_cast<const unsigned char*>(&data[0]);
    unsigned char tag[TAG_LEN];
    std::memcpy(tag, &data[IV_LEN], TAG_LEN);

    const unsigned char* ct = reinterpret_cast<const unsigned char*>(&data[IV_LEN + TAG_LEN]);
    int ct_len = static_cast<int>(data.size()) - IV_LEN - TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::string plain(ct_len, '\0');
    int len = 0, pt_len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
        reinterpret_cast<const unsigned char*>(key32.data()), iv);
    EVP_DecryptUpdate(ctx,
        reinterpret_cast<unsigned char*>(&plain[0]), &len, ct, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    int ret = EVP_DecryptFinal_ex(ctx,
        reinterpret_cast<unsigned char*>(&plain[0]) + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) throw std::runtime_error("AES-GCM auth tag mismatch — message tampered");

    plain.resize(pt_len + len);
    return plain;
}