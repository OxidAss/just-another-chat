#pragma once
#include <string>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <sys/ioctl.h>
#include <unistd.h>

namespace term {

namespace c {
    inline const char* reset()  { return "\033[0m";  }
    inline const char* bold()   { return "\033[1m";  }
    inline const char* dim()    { return "\033[2m";  }
    inline const char* red()    { return "\033[31m"; }
    inline const char* yellow() { return "\033[33m"; }
    inline const char* cyan()   { return "\033[36m"; }
    inline const char* clear()  { return "\r\033[K"; }
}

namespace input {
    inline std::string& buf()  { static std::string s; return s; }
    inline std::string& nick() { static std::string s; return s; }
}

namespace screen {
    inline int& rows() { static int r = 24; return r; }
    inline int& cols() { static int c = 80; return c; }
    inline bool& active() { static bool b = false; return b; }

    inline int query_rows() {
        struct winsize ws{};
        if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > 2)
            return static_cast<int>(ws.ws_row);
        return 24;
    }

    inline int query_cols() {
        struct winsize ws{};
        if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 10)
            return static_cast<int>(ws.ws_col);
        return 80;
    }

    inline void init() {
        rows() = query_rows();
        cols() = query_cols();
        std::cout
            << "\033[1;" << (rows() - 1) << "r"
            << "\033[" << rows() << ";1H"
            << "\033[2K"
            << std::flush;
        active() = true;
    }

    inline void resize() {
        rows() = query_rows();
        cols() = query_cols();
        std::cout
            << "\033[1;" << (rows() - 1) << "r"
            << "\033[" << rows() << ";1H"
            << "\033[2K"
            << std::flush;
    }

    inline void cleanup() {
        active() = false;
        std::cout
            << "\033[r"
            << "\033[" << rows() << ";1H"
            << "\033[2K\n"
            << std::flush;
    }
}

inline std::string ts() {
    std::time_t t  = std::time(nullptr);
    std::tm*    tm = std::localtime(&t);
    char buf[9];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
             tm->tm_hour, tm->tm_min, tm->tm_sec);
    return buf;
}

inline size_t utf8_len(const std::string& s) {
    size_t count = 0;
    for (size_t i = 0; i < s.size(); ) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) i += 1;
        else if ((c & 0xE0) == 0xC0) i += 2;
        else if ((c & 0xF0) == 0xE0) i += 3;
        else if ((c & 0xF8) == 0xF0) i += 4;
        else i += 1;
        count++;
    }
    return count;
}

inline std::string utf8_tail(const std::string& s, size_t max_chars) {
    size_t total = utf8_len(s);
    if (total <= max_chars) return s;
    size_t skip = total - max_chars;
    size_t i = 0;
    for (size_t c = 0; c < skip && i < s.size(); c++) {
        unsigned char ch = static_cast<unsigned char>(s[i]);
        if (ch < 0x80) i += 1;
        else if ((ch & 0xE0) == 0xC0) i += 2;
        else if ((ch & 0xF0) == 0xE0) i += 3;
        else if ((ch & 0xF8) == 0xF0) i += 4;
        else i += 1;
    }
    return s.substr(i);
}

inline void _redraw_input() {
    if (!screen::active() || input::nick().empty()) return;
    int r = screen::rows();
    int c_total = screen::cols();

    std::string prefix_plain = "[" + input::nick() + "] ▸ ";
    size_t prefix_len = prefix_plain.size();

    size_t avail_cols = (c_total > static_cast<int>(prefix_len + 1)) ?
                        (c_total - prefix_len - 1) : 1;

    std::string visible_buf = utf8_tail(input::buf(), avail_cols);

    std::cout
        << "\033[" << r << ";1H"
        << "\033[2K"
        << c::dim()  << "["  << c::reset()
        << c::bold() << input::nick() << c::reset()
        << c::dim()  << "]"  << c::reset()
        << c::cyan() << " ▸ " << c::reset()
        << visible_buf
        << std::flush;
}

inline void _emit(const std::string& line) {
    if (!screen::active()) {
        std::cout << c::clear() << line << "\n" << std::flush;
        return;
    }
    int r = screen::rows();
    std::cout
        << "\033[" << (r - 1) << ";1H"
        << "\n"
        << "\r\033[K"
        << line;
    _redraw_input();
}

inline std::string nick_color(const std::string& nick) {
    if (nick == "server") return "\033[1;35m";
    static const char* palette[] = {
        "\033[1;34m",
        "\033[1;32m",
        "\033[1;36m",
        "\033[1;33m",
        "\033[1;94m",
        "\033[1;92m",
        "\033[1;96m",
        "\033[1;95m",
    };
    size_t hash = 0;
    for (char c : nick) hash = hash * 31 + static_cast<unsigned char>(c);
    return palette[hash % 8];
}

inline void clear_screen() {
    if (!screen::active()) return;
    std::cout << "\033[2J\033[1;1H" << std::flush;
    screen::init();
    _redraw_input();
}

inline void msg(const std::string& nick, const std::string& text) {
    std::ostringstream s;
    s << c::dim()  << "[" << ts() << "] " << c::reset()
      << nick_color(nick) << nick << c::reset()
      << c::dim()  << ": " << c::reset()
      << text;
    _emit(s.str());
}

inline void sys(const std::string& text) {
    std::ostringstream s;
    s << c::dim()  << "[" << ts() << "] "
      << c::cyan() << "* " << c::reset()
      << c::dim()  << text << c::reset();
    _emit(s.str());
}

inline void err(const std::string& text) {
    std::ostringstream s;
    s << c::dim() << "[" << ts() << "] "
      << c::red() << "! " << c::reset()
      << text;
    _emit(s.str());
}

inline void sec(const std::string& text) {
    std::ostringstream s;
    s << c::dim()    << "[" << ts() << "] "
      << c::yellow() << "~ " << c::reset()
      << text;
    _emit(s.str());
}

inline void prompt(const std::string& nick) {
    std::cout
        << c::dim()  << "["  << c::reset()
        << nick_color(nick) << nick << c::reset()
        << c::dim()  << "]"  << c::reset()
        << c::cyan() << " ▸ " << c::reset()
        << std::flush;
}

}