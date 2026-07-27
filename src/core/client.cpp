#include "client.h"
#include "protocol.h"
#include "../net/socket_utils.h"
#include "../common/crypto.h"
#include "../common/sync.h"
#include "../common/term.h"

#include <thread>
#include <atomic>
#include <string>
#include <iostream>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <termios.h>
#include <signal.h>
#include <chrono>

static constexpr size_t MAX_MSG_LEN = 2048;

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

static std::atomic<bool> g_resized{false};
static void on_sigwinch(int) { g_resized = true; }

static bool do_handshake(int fd, const std::string& nick, const std::string& raw_key) {
    std::string hex;
    hex.reserve(raw_key.size() * 2);
    for (unsigned char c : raw_key) {
        char buf[3]; snprintf(buf, sizeof(buf), "%02x", c);
        hex += buf;
    }
    if (!send_frame(fd, nick + ":" + hex)) return false;
    std::string resp;
    if (!recv_frame(fd, resp)) return false;
    if (resp.rfind("ERR", 0) == 0) { term::err("server rejected: " + resp.substr(4)); return false; }
    return resp == "OK";
}

static bool run_session(const std::string& host, int port,
                        const std::string& nick,
                        const std::string& passphrase,
                        const ClientOpts&  opts)
{
    const std::string raw_key = derive_key(passphrase);

    term::sys("connecting to " + host + ":" + std::to_string(port));

    int fd;
    try { fd = connect_to_server(host, port, opts.timeout_sec); }
    catch (const std::exception& e) { term::err(e.what()); return false; }

    if (!do_handshake(fd, nick, raw_key)) { close(fd); return false; }

    term::sys("connected  enc=AES-256-GCM");
    term::sys("commands: /quit  /who  /help");

    std::atomic<bool> alive{true};
    std::atomic<bool> user_quit{false};

    std::thread recv_t([&, fd]() {
        while (alive) {
            std::string frame;
            if (!recv_frame(fd, frame)) break;

            std::string plain;
            try { plain = aes_decrypt(frame, raw_key); }
            catch (const std::exception& e) {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::sec("auth failed: " + std::string(e.what()));
                continue;
            }

            Message msg;
            if (!Message::decode(plain, msg)) continue;

            if (msg.type == MsgType::CHAT) {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::msg(msg.nick, msg.payload);
            } else if (msg.type == MsgType::LIST_RESP) {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::sys(msg.payload);
            } else if (msg.type == MsgType::PING) {
                Message pong; pong.type = MsgType::PONG; pong.nick = nick;
                try { send_frame(fd, aes_encrypt(pong.encode(), raw_key)); } catch (...) {}
            } else if (msg.type == MsgType::QUIT) {
                alive = false;
            }
        }
        alive = false;
        shutdown(fd, SHUT_RDWR);
    });

    term::sys("press Enter to start chatting...");

    RawTerm raw_term;
    signal(SIGWINCH, on_sigwinch);

    { char ch; while (read(STDIN_FILENO, &ch, 1) > 0 && ch != '\n' && ch != '\r') {} }

    {
        std::lock_guard<std::mutex> lk(cout_mutex);
        term::screen::init();
        term::input::nick() = nick;
        term::input::buf().clear();
        term::_redraw_input();
    }

    while (alive) {
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
                }
            }

            if (text.empty()) continue;

            if (text == "/quit" || text == "/exit") {
                Message q; q.type = MsgType::QUIT; q.nick = nick;
                try { send_frame(fd, aes_encrypt(q.encode(), raw_key)); } catch (...) {}
                user_quit = true;
                alive = false;
                break;
            }
            if (text == "/clear") {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::clear_screen();
                continue;
            }
            if (text == "/who") {
                Message req; req.type = MsgType::LIST_REQ; req.nick = nick;
                try { send_frame(fd, aes_encrypt(req.encode(), raw_key)); } catch (...) {}
                continue;
            }
            if (text == "/help") {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::sys("/quit    disconnect");
                term::sys("/who     list online users");
                term::sys("/clear   clear screen");
                term::sys("/help    this message");
                continue;
            }
            if (text.size() > MAX_MSG_LEN) {
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::err("message too long (max " + std::to_string(MAX_MSG_LEN) + " chars)");
                continue;
            }

            Message m; m.type = MsgType::CHAT; m.nick = nick; m.payload = text;
            try {
                if (!send_frame(fd, aes_encrypt(m.encode(), raw_key))) {
                    std::lock_guard<std::mutex> lk(cout_mutex);
                    term::err("send failed — connection lost");
                    alive = false; break;
                }
                std::lock_guard<std::mutex> lk(cout_mutex);
                term::msg(nick, text);
            } catch (const std::exception& e) {
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

    alive = false;
    close(fd);
    recv_t.join();
    return user_quit.load();
}

void run_client(const std::string& host, int port,
                const std::string& nick,
                const std::string& passphrase,
                const ClientOpts&  opts)
{
    for (int attempt = 0; attempt <= opts.reconnect_attempts; attempt++) {
        if (attempt > 0) {
            term::sys("reconnecting in " +
                      std::to_string(opts.reconnect_delay_ms / 1000) +
                      "s  (" + std::to_string(attempt) + "/" +
                      std::to_string(opts.reconnect_attempts) + ")");
            std::this_thread::sleep_for(std::chrono::milliseconds(opts.reconnect_delay_ms));
        }
        if (run_session(host, port, nick, passphrase, opts)) {
            term::sys("disconnected");
            return;
        }
    }
    term::err("could not connect after " + std::to_string(opts.reconnect_attempts) + " attempts");
}