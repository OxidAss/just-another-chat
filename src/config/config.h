#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

struct ServiceEntry {
    std::string name;
    std::string host;
    int         port;
    std::string description;
};

struct AppDefaults {
    int port               = 5050;
    int timeout_sec        = 30;
    int heartbeat_interval = 10;
    int max_clients        = 16;
    int reconnect_attempts = 3;
    int reconnect_delay_ms = 2000;
};

struct AppConfig {
    std::vector<ServiceEntry> services;
    AppDefaults               defaults;
};

// json config parser
namespace cfg {

inline std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n\"");
    size_t b = s.find_last_not_of(" \t\r\n\"");
    if (a == std::string::npos) return "";
    return s.substr(a, b - a + 1);
}

inline std::string value_for(const std::string& block, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = block.find(search);
    if (pos == std::string::npos) return "";
    pos = block.find(':', pos);
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < block.size() && (block[pos]==' '||block[pos]=='\t')) pos++;
    if (block[pos] == '"') {
        size_t end = block.find('"', pos + 1);
        return block.substr(pos + 1, end - pos - 1);
    }
    size_t end = block.find_first_of(",}\n", pos);
    return trim(block.substr(pos, end - pos));
}

inline AppConfig load(const std::string& path) {
    AppConfig cfg;
    std::ifstream f(path);
    if (!f.is_open()) {
        std::cerr << "[config] Cannot open " << path << ", using defaults\n";
        return cfg;
    }

    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    // parse services array
    size_t arr_start = content.find("\"services\"");
    if (arr_start != std::string::npos) {
        size_t bracket = content.find('[', arr_start);
        int depth = 0;
        size_t i = bracket;
        for (; i < content.size(); i++) {
            if (content[i] == '{') {
                if (depth == 0) {
                    size_t obj_start = i;
                    // find closing }
                    int d = 0;
                    for (size_t j = i; j < content.size(); j++) {
                        if (content[j] == '{') d++;
                        if (content[j] == '}') { d--; if (d == 0) {
                            std::string block = content.substr(obj_start, j - obj_start + 1);
                            ServiceEntry e;
                            e.name        = value_for(block, "name");
                            e.host        = value_for(block, "host");
                            std::string ps = value_for(block, "port");
                            e.port        = ps.empty() ? 5050 : std::stoi(ps);
                            e.description = value_for(block, "description");
                            if (!e.name.empty()) cfg.services.push_back(e);
                            i = j;
                            break;
                        }}
                    }
                }
            }
            if (content[i] == '[') depth++;
            if (content[i] == ']') { if (depth-- == 0) break; }
        }
    }

    // parse defaults
    size_t def_start = content.find("\"defaults\"");
    if (def_start != std::string::npos) {
        size_t brace = content.find('{', def_start);
        size_t end   = content.find('}', brace);
        std::string block = content.substr(brace, end - brace + 1);

        auto iv = [&](const std::string& k, int& out) {
            std::string v = value_for(block, k);
            if (!v.empty()) out = std::stoi(v);
        };
        iv("port",                  cfg.defaults.port);
        iv("timeout_sec",           cfg.defaults.timeout_sec);
        iv("heartbeat_interval_sec",cfg.defaults.heartbeat_interval);
        iv("max_clients",           cfg.defaults.max_clients);
        iv("reconnect_attempts",    cfg.defaults.reconnect_attempts);
        iv("reconnect_delay_ms",    cfg.defaults.reconnect_delay_ms);
    }

    return cfg;
}

}