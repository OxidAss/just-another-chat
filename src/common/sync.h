#pragma once
#include <mutex>
#include <string>

extern std::mutex cout_mutex;

void safe_print(const std::string& text);