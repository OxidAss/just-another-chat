#pragma once
#include <string>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>

namespace term {

// ansi
namespace c {
    inline const char* reset()  { return "\033[0m";   }
    inline const char* bold()   { return "\033[1m";   }
    inline const char* dim()    { return "\033[2m";   }
    inline const char* red()    { return "\033[31m";  }
    inline const char* green()  { return "\033[32m";  }
    inline const char* yellow() { return "\033[33m";  }
    inline const char* cyan()   { return "\033[36m";  }
    inline const char* white()  { return "\033[37m";  }
    inline const char* clear()  { return "\r\033[K";  }
}

inline std::string ts() {
    std::time_t t  = std::time(nullptr);
    std::tm*    tm = std::localtime(&t);
    char buf[9];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
             tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buf;
}

// [hh:mm:ss] nick: message
inline void msg(const std::string& nick, const std::string& text) {
    std::cout << c::clear()
              << c::dim() << "[" << ts() << "] "
              << c::reset() << c::bold() << nick << c::reset()
              << c::dim()  << ": "       << c::reset()
              << text << "\n";
}

// [hh:mm:ss] * system notice
inline void sys(const std::string& text) {
    std::cout << c::clear()
              << c::dim()  << "[" << ts() << "] "
              << c::cyan() << "* " << c::reset()
              << c::dim()  << text << c::reset() << "\n";
}

// [hh:mm:ss] ! error
inline void err(const std::string& text) {
    std::cout << c::clear()
              << c::dim()   << "[" << ts() << "] "
              << c::red()   << "! " << c::reset()
              << text << "\n";
}

// [hh:mm:ss] ~ security warning
inline void sec(const std::string& text) {
    std::cout << c::clear()
              << c::dim()    << "[" << ts() << "] "
              << c::yellow() << "~ " << c::reset()
              << text << "\n";
}

// input prompt
inline void prompt(const std::string& nick) {
    std::cout << c::dim() << nick << c::reset()
              << c::dim() << "> " << c::reset()
              << std::flush;
}

}