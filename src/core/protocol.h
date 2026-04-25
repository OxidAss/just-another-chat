#pragma once
#include <string>
#include <cstdint>

// wire message types
enum class MsgType : uint8_t {
    HANDSHAKE = 0x01,  // "nick\0passphrase-hash" — sent unencrypted once
    CHAT      = 0x02,  // normal chat text
    PING      = 0x03,  // heartbeat ping
    PONG      = 0x04,  // heartbeat pong
    QUIT      = 0x05,  // graceful disconnect
    SERVER_OK = 0x06,  // server accepted handshake
    SERVER_ERR= 0x07,  // server rejected (wrong key, etc.)
};

struct Message {
    MsgType     type;
    std::string nick;
    std::string payload;

    // serialyze
    std::string encode() const {
        std::string out;
        out += static_cast<char>(type);
        out += static_cast<char>(nick.size() & 0xFF);
        out += nick;
        out += payload;
        return out;
    }

    // returns data on false format
    static bool decode(const std::string& raw, Message& msg) {
        if (raw.size() < 2) return false;
        msg.type = static_cast<MsgType>(static_cast<uint8_t>(raw[0]));
        size_t nick_len = static_cast<uint8_t>(raw[1]);
        if (raw.size() < 2 + nick_len) return false;
        msg.nick    = raw.substr(2, nick_len);
        msg.payload = raw.substr(2 + nick_len);
        return true;
    }
};