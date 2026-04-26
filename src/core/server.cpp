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
#include <unordered_map>
#include <string>
#include <iostream>
#include <algorithm>
#include <unistd.h>
#include <sys/socket.h>
#include <chrono>

// limits
static constexpr size_t MAX_NICK_LEN    = 32;
static constexpr size_t MAX_MSG_LEN     = 2048;
static constexpr int    RATE_WINDOW_SEC = 10;   // sliding window
static constexpr int    RATE_MAX_CONN   = 5;    // max new conns per IP per window

struct Peer {
    int         fd;
    std::string nick;
    std::string addr;
    std::chrono::steady_clock::time_point last_pong;
};

static std::mutex          peers_mx;
static std::map<int, Peer> peers;
static std::atomic<bool>   running{true};

// rate limiting — tracks connection timestamps per IP
static std::mutex rate_mx;
static std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> rate_map;

static bool rate_check(const std::string& ip) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(rate_mx);
    auto& times = rate_map[ip];
    // evict old entries outside the window
    times.erase(std::remove_if(times.begin(), times.end(), [&](auto& t) {
        return std::chrono::duration_cast<std::chrono::seconds>(now - t).count() > RATE_WINDOW_SEC;
    }), times.end());
    if ((int)times.size() >= RATE_MAX_CONN) return false;
    times.push_back(now);
    return true;
}

static bool valid_nick(const std::string& nick) {
    if (nick.empty() || nick.size() > MAX_NICK_LEN) return false;
    for (char c : nick)
        if (!isalnum(c) && c != '_' && c != '-') return false;
    return true;
}

static void broadcast(const std::string& frame, int exclude_fd = -1) {
    std::lock_guard<std::mutex> lk(peers_mx);
    for (auto& [fd, _] : peers)
        if (fd != exclude_fd) send_frame(fd, frame);
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

static void handle_client(int fd, std::string passphrase, int heartbeat_sec) {
    const std::string addr = peer_addr(fd);

    // rate limit check
    // extract IP without port for rate limiting
    std::string ip = addr;
    auto colon = addr.rfind(':');
    if (colon != std::string::npos) ip = addr.substr(0, colon);

    if (!rate_check(ip)) {
        send_frame(fd, "ERR:rate_limited");
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sec("rate limited: " + addr);
        close(fd); return;
    }

    std::string hs;
    if (!recv_frame(fd, hs)) { close(fd); return; }

    auto sep = hs.find(':');
    if (sep == std::string::npos) {
        send_frame(fd, "ERR:bad_handshake");
        close(fd); return;
    }

    const std::string nick    = hs.substr(0, sep);
    const std::string claimed = hs.substr(sep + 1);

    // nick validation
    if (!valid_nick(nick)) {
        send_frame(fd, "ERR:invalid_nick");
        close(fd); return;
    }

    // check nick uniqueness
    {
        std::lock_guard<std::mutex> lk(peers_mx);
        for (auto& [_, p] : peers) {
            if (p.nick == nick) {
                send_frame(fd, "ERR:nick_taken");
                close(fd); return;
            }
        }
    }

    const std::string raw_key = derive_key(passphrase);

    std::string expected;
    expected.reserve(raw_key.size() * 2);
    for (unsigned char c : raw_key) {
        char buf[3]; snprintf(buf, sizeof(buf), "%02x", c);
        expected += buf;
    }

    if (claimed != expected) {
        send_frame(fd, "ERR:wrong_key");
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sec("rejected " + nick + " (" + addr + ") — wrong passphrase");
        close(fd); return;
    }

    {
        std::lock_guard<std::mutex> lk(peers_mx);
        peers[fd] = Peer{ fd, nick, addr, std::chrono::steady_clock::now() };
    }
    send_frame(fd, "OK");

    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sys("connected: " + nick + " (" + addr + ")  [total: " +
                  std::to_string(peer_count()) + "]");
    }

    {
        Message m; m.type = MsgType::CHAT; m.nick = "server"; m.payload = nick + " joined";
        try { broadcast(aes_encrypt(m.encode(), raw_key), fd); } catch (...) {}
    }

    std::atomic<bool> alive{true};

    std::thread hb([&, fd]() {
        while (alive) {
            std::this_thread::sleep_for(std::chrono::seconds(heartbeat_sec));
            if (!alive) break;
            Message ping; ping.type = MsgType::PING; ping.nick = "server";
            try {
                if (!send_frame(fd, aes_encrypt(ping.encode(), raw_key))) break;
            } catch (...) { break; }

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
                }
            }
        }
        shutdown(fd, SHUT_RDWR);
    });

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

        if (msg.type == MsgType::CHAT) {
            // enforce message length limit
            if (msg.payload.size() > MAX_MSG_LEN) {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::sec("oversized message from " + nick + " — dropped");
                continue;
            }
            {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::msg(msg.nick, msg.payload);
                term::prompt("server");
            }
            broadcast(frame, fd);
        } else if (msg.type == MsgType::PONG) {
            std::lock_guard<std::mutex> lk(peers_mx);
            auto it = peers.find(fd);
            if (it != peers.end())
                it->second.last_pong = std::chrono::steady_clock::now();
        } else if (msg.type == MsgType::QUIT) {
            alive = false;
        }
    }

    alive = false;
    hb.detach();
    drop_peer(fd);

    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sys("disconnected: " + nick + " (" + addr + ")  [total: " +
                  std::to_string(peer_count()) + "]");
    }

    {
        Message m; m.type = MsgType::CHAT; m.nick = "server"; m.payload = nick + " left";
        try { broadcast(aes_encrypt(m.encode(), raw_key)); } catch (...) {}
    }
}

static void operator_loop(const std::string& raw_key) {
    term::sys("press Enter to start chatting...");
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
                term::sys("  " + p.nick + " (" + p.addr + ") [fd=" + std::to_string(fd) + "]");
            continue;
        }

        Message m; m.type = MsgType::CHAT; m.nick = "server"; m.payload = text;
        try { broadcast(aes_encrypt(m.encode(), raw_key)); }
        catch (const std::exception& e) { term::err(e.what()); }
    }
}

void run_server(const std::string& passphrase, const ServerOpts& opts) {
    const std::string raw_key = derive_key(passphrase);

    int sfd;
    try { sfd = create_server_socket(opts.port); }
    catch (const std::exception& e) { term::err(e.what()); return; }

    term::sys("jschat server  port=" + std::to_string(opts.port) +
              "  enc=AES-256-GCM  IPv4+IPv6");
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
            std::thread(handle_client, cfd, passphrase, opts.heartbeat_sec).detach();
        }
    });

    operator_loop(raw_key);

    running = false;
    close(sfd);
    accept_t.detach();
}