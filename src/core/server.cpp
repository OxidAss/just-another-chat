#include "server.h"
#include "protocol.h"
#include "../net/socket_utils.h"
#include "../common/crypto.h"
#include "../common/sync.h"
#include "../common/term.h"

#include <thread>
#include <atomic>
#include <mutex>
#include <map>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <chrono>
#include <csignal>

// client registry

struct Peer {
    int         fd;
    std::string nick;
    std::chrono::steady_clock::time_point last_pong;
};

static std::mutex              peers_mx;
static std::map<int, Peer>     peers;
static std::atomic<bool>       running{true};

static void broadcast(const std::string& enc_frame, int exclude_fd = -1) {
    std::lock_guard<std::mutex> lk(peers_mx);
    for (auto& [fd, _] : peers)
        if (fd != exclude_fd) send_frame(fd, enc_frame);
}

static size_t peer_count() {
    std::lock_guard<std::mutex> lk(peers_mx);
    return peers.size();
}

static void drop_peer(int fd) {
    std::lock_guard<std::mutex> lk(peers_mx);
    peers.erase(fd);
    close(fd);
}

// perclient handler

static void handle_client(int fd, std::string key, int heartbeat_sec) {
    std::string hs;
    if (!recv_frame(fd, hs)) { close(fd); return; }

    auto sep = hs.find(':');
    if (sep == std::string::npos) {
        send_frame(fd, "ERR:bad_handshake");
        close(fd); return;
    }

    std::string nick    = hs.substr(0, sep);
    std::string claimed = hs.substr(sep + 1);

    // build expected hash
    std::string raw_key = derive_key(key); // key IS the passphrase here
    std::string expected;
    for (unsigned char c : raw_key) {
        char buf[3]; snprintf(buf, sizeof(buf), "%02x", c);
        expected += buf;
    }

    if (claimed != expected) {
        send_frame(fd, "ERR:wrong_key");
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sec("rejected " + nick + " — wrong passphrase");
        close(fd); return;
    }

    // register
    {
        std::lock_guard<std::mutex> lk(peers_mx);
        peers[fd] = Peer{ fd, nick, std::chrono::steady_clock::now() };
    }
    send_frame(fd, "OK");

    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sys("connected: " + nick + "  [total: " +
                  std::to_string(peer_count()) + "]");
    }

    // join notif
    {
        Message m; m.type = MsgType::CHAT; m.nick = "server";
        m.payload = nick + " joined";
        try { broadcast(aes_encrypt(m.encode(), raw_key), fd); } catch (...) {}
    }

    // heartbeat sender
    std::atomic<bool> alive{true};
    std::thread hb([&, fd]() {
        while (alive) {
            std::this_thread::sleep_for(std::chrono::seconds(heartbeat_sec));
            if (!alive) break;

            Message ping; ping.type = MsgType::PING; ping.nick = "server";
            try {
                if (!send_frame(fd, aes_encrypt(ping.encode(), raw_key))) break;
            } catch (...) { break; }

            // Timeout check
            auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lk(peers_mx);
            auto it = peers.find(fd);
            if (it != peers.end()) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.last_pong).count();
                if (age > heartbeat_sec * 2) {
                    std::lock_guard<std::mutex> lk2(cout_mutex);
                    term::sys(nick + " timed out");
                    alive = false;
                    break;
                }
            }
        }
        shutdown(fd, SHUT_RDWR);
    });

    // recv loop
    while (alive) {
        std::string frame;
        if (!recv_frame(fd, frame)) break;

        std::string plain;
        try { plain = aes_decrypt(frame, raw_key); }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lk(cout_mutex);
            term::sec("tampered message from " + nick + ": " + e.what());
            continue;
        }

        Message msg;
        if (!Message::decode(plain, msg)) continue;

        switch (msg.type) {
            case MsgType::CHAT: {
                {
                    std::lock_guard<std::mutex> lk(cout_mutex);
                    term::msg(msg.nick, msg.payload);
                    term::prompt("server");
                }
                broadcast(frame, fd);
                break;
            }
            case MsgType::PONG: {
                std::lock_guard<std::mutex> lk(peers_mx);
                auto it = peers.find(fd);
                if (it != peers.end())
                    it->second.last_pong = std::chrono::steady_clock::now();
                break;
            }
            case MsgType::QUIT:
                alive = false;
                break;
            default: break;
        }
    }

    alive = false;
    hb.detach();
    drop_peer(fd);

    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sys("disconnected: " + nick + "  [total: " +
                  std::to_string(peer_count()) + "]");
    }

    // leave announcment
    {
        Message m; m.type = MsgType::CHAT; m.nick = "server";
        m.payload = nick + " left";
        try { broadcast(aes_encrypt(m.encode(), raw_key)); } catch (...) {}
    }
}

// server input

static void operator_loop(const std::string& raw_key) {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    while (running) {
        term::prompt("server");
        std::string text;
        if (!std::getline(std::cin, text)) break;
        if (text.empty()) continue;
        if (text == "/quit") { running = false; break; }
        if (text == "/who") {
            std::lock_guard<std::mutex> lk(peers_mx);
            std::lock_guard<std::mutex> lk2(cout_mutex);
            term::sys("online: " + std::to_string(peers.size()) + " client(s)");
            for (auto& [fd, p] : peers)
                term::sys("  " + p.nick + " [fd=" + std::to_string(fd) + "]");
            continue;
        }

        Message m; m.type = MsgType::CHAT; m.nick = "server"; m.payload = text;
        try { broadcast(aes_encrypt(m.encode(), raw_key)); }
        catch (const std::exception& e) { term::err(e.what()); }
    }
}

// entry

void run_server(const std::string& passphrase, const ServerOpts& opts) {
    std::string raw_key = derive_key(passphrase);

    int sfd;
    try { sfd = create_server_socket(opts.port); }
    catch (const std::exception& e) { term::err(e.what()); return; }

    term::sys("jschat server  port=" + std::to_string(opts.port) +
              "  enc=AES-256-GCM");
    term::sys("commands: /who  /quit");

    std::thread accept_t([&, sfd]() {
        while (running) {
            int cfd = accept_client(sfd);
            if (cfd < 0) break;
            {
                std::lock_guard<std::mutex> lk(peers_mx);
                if ((int)peers.size() >= opts.max_clients) {
                    send_frame(cfd, "ERR:server_full");
                    close(cfd); continue;
                }
            }
            std::thread(handle_client, cfd,
                        passphrase, opts.heartbeat_sec).detach();
        }
    });

    operator_loop(raw_key);

    running = false;
    close(sfd);
    accept_t.detach();
}