#pragma once
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <iostream>
#include <vector>
#include <mutex>

// ── ANSI escape helpers ─────────────────────────────────────────────────────
namespace ansi {
    inline const char* reset()  { return "\033[0m";  }
    inline const char* bold()   { return "\033[1m";  }
    inline const char* dim()    { return "\033[2m";  }
    inline const char* italic() { return "\033[3m";  }

    // 256-color fg
    inline std::string fg(int n) {
        return "\033[38;5;" + std::to_string(n) + "m";
    }
    // 256-color bg
    inline std::string bg(int n) {
        return "\033[48;5;" + std::to_string(n) + "m";
    }

    // Palette
    inline std::string accent()  { return fg(75);  }   // #5fafff  blue
    inline std::string success() { return fg(83);  }   // #5fff5f  green
    inline std::string warn()    { return fg(214); }   // #ffaf00  amber
    inline std::string error()   { return fg(196); }   // #ff0000  red
    inline std::string muted()   { return fg(242); }   // #6c6c6c  gray
    inline std::string white()   { return fg(255); }   // #eeeeee  white
    inline std::string cyan()    { return fg(87);  }   // #5fffff
    inline std::string purple()  { return fg(141); }   // #af87ff

    // Named peer colors (cycle through for multi-client)
    inline std::string peer_color(int id) {
        static const int palette[] = {39,214,141,83,196,87,220,204};
        return fg(palette[id % 8]);
    }

    inline const char* clear_line() { return "\r\033[K"; }
}

// ── Time ────────────────────────────────────────────────────────────────────
inline std::string timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm*    tm = std::localtime(&t);
    std::ostringstream ss;
    ss << std::setfill('0')
       << std::setw(2) << tm->tm_hour << ":"
       << std::setw(2) << tm->tm_min  << ":"
       << std::setw(2) << tm->tm_sec;
    return ss.str();
}

// ui
namespace ui {

inline void banner() {
    std::cout
        << "\n"
        << ansi::accent() << ansi::bold()
        << "  ╔══════════════════════════════════════╗\n"
        << "  ║              jsAnotherChat           ║\n"
        << "  ║       AES-256-GCM  ·  end-to-end     ║\n"
        << "  ╚══════════════════════════════════════╝\n"
        << ansi::reset() << "\n";
}

inline void separator() {
    std::cout << ansi::muted()
              << "  ────────────────────────────────────────\n"
              << ansi::reset();
}

// status
inline void sys(const std::string& msg) {
    std::cout << ansi::clear_line()
              << ansi::muted() << "  [" << timestamp() << "] "
              << ansi::cyan() << "· " << ansi::white() << msg
              << ansi::reset() << "\n";
}

// error
inline void err(const std::string& msg) {
    std::cout << ansi::clear_line()
              << ansi::muted() << "  [" << timestamp() << "] "
              << ansi::error() << "✗ " << ansi::white() << msg
              << ansi::reset() << "\n";
}

// connected
inline void ok(const std::string& msg) {
    std::cout << ansi::clear_line()
              << ansi::muted() << "  [" << timestamp() << "] "
              << ansi::success() << "✓ " << ansi::white() << msg
              << ansi::reset() << "\n";
}

// incoming message
inline void msg_in(const std::string& nick, const std::string& text, int color_id = 0) {
    std::cout << ansi::clear_line()
              << ansi::muted() << "  [" << timestamp() << "] "
              << ansi::peer_color(color_id) << ansi::bold() << nick
              << ansi::reset() << ansi::muted() << " ▸ "
              << ansi::reset() << ansi::white() << text
              << ansi::reset() << "\n";
}

// outgoing prompt
inline void prompt(const std::string& nick) {
    std::cout << ansi::accent() << ansi::bold()
              << "  " << nick
              << ansi::muted() << " ▸ "
              << ansi::reset() << std::flush;
}

// warn
inline void security(const std::string& msg) {
    std::cout << ansi::clear_line()
              << ansi::warn() << "  ⚠  " << ansi::white() << msg
              << ansi::reset() << "\n";
}

// list numbered options
inline void option_list(const std::vector<std::string>& items) {
    for (size_t i = 0; i < items.size(); i++) {
        std::cout << "  "
                  << ansi::accent() << ansi::bold() << "[" << (i+1) << "]"
                  << ansi::reset() << "  " << items[i] << "\n";
    }
}

// ask for input
inline std::string ask(const std::string& prompt_text) {
    std::cout << "\n  " << ansi::accent() << "▶ " << ansi::white()
              << prompt_text << ansi::reset() << "  ";
    std::string line;
    std::getline(std::cin, line);
    // trim
    size_t a = line.find_first_not_of(" \t");
    size_t b = line.find_last_not_of(" \t");
    return (a == std::string::npos) ? "" : line.substr(a, b - a + 1);
}

}