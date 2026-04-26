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
#include <sys/socket.h>
#include <chrono>

static constexpr size_t MAX_MSG_LEN = 2048;

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
                term::prompt(nick);
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
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    while (alive) {
        term::prompt(nick);
        std::string text;
        if (!std::getline(std::cin, text)) break;
        if (text.empty()) continue;

        if (text == "/quit" || text == "/exit") {
            Message q; q.type = MsgType::QUIT; q.nick = nick;
            try { send_frame(fd, aes_encrypt(q.encode(), raw_key)); } catch (...) {}
            user_quit = true;
            alive = false;
            break;
        }
        if (text == "/who") {
            std::lock_guard<std::mutex> lk(cout_mutex);
            term::sys("you are: " + nick);
            continue;
        }
        if (text == "/help") {
            std::lock_guard<std::mutex> lk(cout_mutex);
            term::sys("/quit   disconnect");
            term::sys("/who    show your nick");
            term::sys("/help   this message");
            continue;
        }

        // enforce message length
        if (text.size() > MAX_MSG_LEN) {
            std::lock_guard<std::mutex> lk(cout_mutex);
            term::err("message too long (max " + std::to_string(MAX_MSG_LEN) + " chars)");
            continue;
        }

        Message m; m.type = MsgType::CHAT; m.nick = nick; m.payload = text;
        try {
            if (!send_frame(fd, aes_encrypt(m.encode(), raw_key))) {
                term::err("send failed — connection lost");
                alive = false; break;
            }
        } catch (const std::exception& e) { term::err(e.what()); }
    }

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