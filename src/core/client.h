#pragma once
#include <string>

struct ClientOpts {
    int timeout_sec        = 10;
    int reconnect_attempts = 3;
    int reconnect_delay_ms = 2000;
    int heartbeat_sec      = 15;
};

void run_client(const std::string& ip, int port,
                const std::string& nick,
                const std::string& passphrase,
                const ClientOpts&  opts);