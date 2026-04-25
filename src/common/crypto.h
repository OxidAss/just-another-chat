#pragma once
#include <string>
#include <vector>
#include <stdexcept>

std::string aes_encrypt(const std::string& plaintext, const std::string& key32);
std::string aes_decrypt(const std::string& data, const std::string& key32);
std::string derive_key(const std::string& passphrase);