#pragma once
#include <string>

struct ServerOpts {
    int         port            = 5050;
    int         max_clients     = 32;
    int         heartbeat_sec   = 15;
    int         timeout_sec     = 45;
};

void run_server(const std::string& passphrase, const ServerOpts& opts);