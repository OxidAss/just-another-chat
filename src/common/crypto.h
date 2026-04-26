#pragma once
#include <string>
#include <stdexcept>

// PBKDF2-SHA256, 100k iterations, 32-byte key
std::string derive_key(const std::string& passphrase, const std::string& salt = "");

std::string aes_encrypt(const std::string& plaintext, const std::string& key32);
std::string aes_decrypt(const std::string& data,      const std::string& key32);

// generate random bytes
std::string random_bytes(size_t n);