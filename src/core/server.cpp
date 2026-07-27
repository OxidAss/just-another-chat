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
#include <sys/select.h>
#include <sys/socket.h>
#include <chrono>
#include <vector>
#include <termios.h>
#include <signal.h>

// limits
static constexpr size_t MAX_NICK_LEN    = 32;
static constexpr size_t MAX_MSG_LEN     = 2048;
static constexpr int    RATE_WINDOW_SEC = 10;
static constexpr int    RATE_MAX_CONN   = 5;

namespace {
    struct RawTerm {
        struct termios saved{};
        explicit RawTerm() {
            tcgetattr(STDIN_FILENO, &saved);
            struct termios raw = saved;
            raw.c_lflag &= ~(ICANON | ECHO);
            raw.c_cc[VMIN]  = 0;
            raw.c_cc[VTIME] = 1;
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        }
        ~RawTerm() { tcsetattr(STDIN_FILENO, TCSANOW, &saved); }
    };

    std::atomic<bool> g_resized{false};
    void on_sigwinch(int) { g_resized = true; }
}

struct Peer {
    int         fd;
    std::string nick;
    std::string addr;
    std::chrono::steady_clock::time_point last_pong;
};

static std::mutex          peers_mx;
static std::map<int, Peer> peers;
static std::atomic<bool>   running{true};

// rate limiting
static std::mutex rate_mx;
static std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> rate_map;

static bool rate_check(const std::string& ip) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(rate_mx);
    auto& times = rate_map[ip];
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

    size_t current_peers = peer_count();
    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sys("connected: " + nick + " (" + addr + ")  [total: " +
                  std::to_string(current_peers) + "]");
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
            if (msg.payload.size() > MAX_MSG_LEN) {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::sec("oversized message from " + nick + " — dropped");
                continue;
            }

            if (msg.payload.empty() || msg.payload.find_first_not_of(" \t") == std::string::npos) {
                continue;
            }

            {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::msg(msg.nick, msg.payload);
            }
            broadcast(frame, fd);
        } else if (msg.type == MsgType::LIST_REQ) {
            std::string user_list = "online: ";
            {
                std::lock_guard<std::mutex> lk(peers_mx);
                bool first = true;
                for (auto& [_, p] : peers) {
                    if (!first) user_list += ", ";
                    user_list += p.nick;
                    first = false;
                }
            }
            Message resp; resp.type = MsgType::LIST_RESP; resp.nick = "server"; resp.payload = user_list;
            try { send_frame(fd, aes_encrypt(resp.encode(), raw_key)); } catch (...) {}
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

    size_t final_peers = peer_count();
    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::sys("disconnected: " + nick + " (" + addr + ")  [total: " +
                  std::to_string(final_peers) + "]");
    }

    {
        Message m; m.type = MsgType::CHAT; m.nick = "server"; m.payload = nick + " left";
        try { broadcast(aes_encrypt(m.encode(), raw_key)); } catch (...) {}
    }
}

static void operator_loop(const std::string& raw_key) {
    term::sys("press Enter to start chatting...");

    RawTerm raw_term;
    signal(SIGWINCH, on_sigwinch);

    { char ch; while (read(STDIN_FILENO, &ch, 1) > 0 && ch != '\n' && ch != '\r') {} }

    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::screen::init();
        term::input::nick() = "server";
        term::input::buf().clear();
        term::_redraw_input();
    }

    while (running) {
        if (g_resized.exchange(false)) {
            std::lock_guard<std::mutex> lk(cout_mutex);
            term::screen::resize();
            term::_redraw_input();
        }

        char ch;
        ssize_t n = read(STDIN_FILENO, &ch, 1);
        if (n < 0) break;
        if (n == 0) continue;
        if (ch == '\033') { 
            char seq;
            struct timeval tv{0, 20000};
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(STDIN_FILENO, &fds);
            while (select(STDIN_FILENO + 1, &fds, nullptr, nullptr, &tv) > 0) {
                if (read(STDIN_FILENO, &seq, 1) <= 0) break;
                tv = {0, 10000};
                FD_ZERO(&fds);
                FD_SET(STDIN_FILENO, &fds);
            }
            continue;
        }

        if (ch == '\n' || ch == '\r') {
            std::string text;
            {
                std::lock_guard<std::mutex> lk(cout_mutex);
                text = term::input::buf();
                term::input::buf().clear();
                if (text.empty()) {
                    term::_redraw_input();
                } else {
                    if (text.find_first_not_of(" \t") == std::string::npos) {
                        text = "";
                        term::_redraw_input();
                    }
                }
            }

            if (text.empty()) continue;

            if (text == "/quit" || text == "/exit") { 
                running = false; 
                break; 
            }
            if (text == "/clear") {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::clear_screen();
                continue;
            }

            if (text == "/who") {
                std::vector<std::pair<std::string, std::string>> list;
                size_t total = 0;
                {
                    std::lock_guard<std::mutex> lk(peers_mx);
                    total = peers.size();
                    for (auto& [fd, p] : peers)
                        list.push_back({p.nick, p.addr + " [fd=" + std::to_string(fd) + "]"});
                }
                std::lock_guard<std::mutex> lk2(cout_mutex);
                term::sys("online: " + std::to_string(total) + " client(s)");
                for (auto& item : list)
                    term::sys("  " + item.first + " (" + item.second + ")");
                continue;
            }

            Message m; m.type = MsgType::CHAT; m.nick = "server"; m.payload = text;
            try { 
                broadcast(aes_encrypt(m.encode(), raw_key)); 
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::msg("server", text);
            }
            catch (const std::exception& e) { 
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::err(e.what()); 
            }

        } else if (ch == 127 || ch == '\b') {
            std::lock_guard<std::mutex> lk(cout_mutex);
            std::string& buf = term::input::buf();
            if (!buf.empty()) {
                while (!buf.empty() && (buf.back() & 0xC0) == 0x80) {
                    buf.pop_back();
                }
                if (!buf.empty()) {
                    buf.pop_back();
                }
                term::_redraw_input();
            }

        } else if (static_cast<unsigned char>(ch) >= 32) {
            std::string chars(1, ch);
            unsigned char uc = static_cast<unsigned char>(ch);
            int needed = 0;
            if ((uc & 0xE0) == 0xC0) needed = 1;
            else if ((uc & 0xF0) == 0xE0) needed = 2;
            else if ((uc & 0xF8) == 0xF0) needed = 3;

            for (int i = 0; i < needed; i++) {
                char next_ch;
                if (read(STDIN_FILENO, &next_ch, 1) == 1) {
                    chars += next_ch;
                } else {
                    break;
                }
            }

            std::lock_guard<std::mutex> lk(cout_mutex);
            if (term::input::buf().size() + chars.size() <= MAX_MSG_LEN) {
                term::input::buf() += chars;
                term::_redraw_input();
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::input::nick().clear();
        term::input::buf().clear();
        term::screen::cleanup();
    }
    signal(SIGWINCH, SIG_DFL);
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