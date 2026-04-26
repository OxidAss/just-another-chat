#include "core/server.h"
#include "core/client.h"
#include "common/term.h"

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

static void print_usage(const char* argv0) {
    std::cout
        << "usage:\n"
        << "  " << argv0 << " -s <port> <passphrase>\n"
        << "  " << argv0 << " -c <host> <passphrase> <nickname>\n"
        << "\nexamples:\n"
        << "  " << argv0 << " -s 5050 mysecret\n"
        << "  " << argv0 << " -c 127.0.0.1 mysecret alice\n"
        << "\noptions:\n"
        << "  -s   start server\n"
        << "  -c   connect as client\n"
        << "  -h   show this help\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    const char* flag = argv[1];

    if (strcmp(flag, "-h") == 0 || strcmp(flag, "--help") == 0) {
        print_usage(argv[0]); return 0;
    }

    if (strcmp(flag, "-s") == 0) {
        if (argc < 4) {
            std::cerr << "error: -s requires <port> <passphrase>\n";
            print_usage(argv[0]); return 1;
        }
        int port = std::atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            std::cerr << "error: invalid port '" << argv[2] << "'\n"; return 1;
        }
        ServerOpts opts;
        opts.port = port;
        if (const char* v = std::getenv("JSCHAT_MAX_CLIENTS")) opts.max_clients   = std::atoi(v);
        if (const char* v = std::getenv("JSCHAT_HEARTBEAT"))   opts.heartbeat_sec = std::atoi(v);
        run_server(argv[3], opts);
        return 0;
    }

    if (strcmp(flag, "-c") == 0) {
        if (argc < 5) {
            std::cerr << "error: -c requires <host> <passphrase> <nickname>\n";
            print_usage(argv[0]); return 1;
        }
        std::string host = argv[2];
        int port = 5050;
        auto colon = host.find(':');
        if (colon != std::string::npos) {
            port = std::atoi(host.substr(colon + 1).c_str());
            host = host.substr(0, colon);
        }
        ClientOpts opts;
        if (const char* v = std::getenv("JSCHAT_PORT"))      port                   = std::atoi(v);
        if (const char* v = std::getenv("JSCHAT_TIMEOUT"))   opts.timeout_sec       = std::atoi(v);
        if (const char* v = std::getenv("JSCHAT_RECONNECT")) opts.reconnect_attempts = std::atoi(v);
        run_client(host, port, argv[4], argv[3], opts);
        return 0;
    }

    std::cerr << "error: unknown flag '" << flag << "'\n";
    print_usage(argv[0]);
    return 1;
}