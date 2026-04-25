#include "sync.h"
#include <iostream>

std::mutex cout_mutex;

void safe_print(const std::string& text) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << text << std::endl;
}