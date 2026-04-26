#include "socket_utils.h"

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <stdexcept>
#include <cerrno>

static void set_keepalive(int fd) {
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
#ifdef TCP_KEEPIDLE
    int idle = 20;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
    int intvl = 5, cnt = 3;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,   &cnt,   sizeof(cnt));
}

static bool send_all(int fd, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

static bool recv_all(int fd, char* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

// IPv6 dual-stack server socket
// IPV6_V6ONLY=0 means it also accepts IPv4 connections (mapped as ::ffff:x.x.x.x)
int create_server_socket(int port) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket() failed: " + std::string(strerror(errno)));

    int yes = 1, no = 0;
    setsockopt(fd, SOL_SOCKET,   SO_REUSEADDR,  &yes, sizeof(yes));
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,   &no,  sizeof(no));  // dual-stack

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr   = in6addr_any;
    addr.sin6_port   = htons(port);

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        throw std::runtime_error("bind() failed: " + std::string(strerror(errno)));
    }
    if (listen(fd, 32) < 0) {
        close(fd);
        throw std::runtime_error("listen() failed");
    }
    return fd;
}

int accept_client(int server_fd) {
    sockaddr_in6 addr{};
    socklen_t    len = sizeof(addr);
    int fd = accept(server_fd, reinterpret_cast<sockaddr*>(&addr), &len);
    if (fd >= 0) set_keepalive(fd);
    return fd;
}

// resolves host via getaddrinfo — supports IPv4, IPv6, hostnames
int connect_to_server(const std::string& host, int port, int timeout_sec) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;    // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    const std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0)
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(rc)));

    int fd = -1;
    for (addrinfo* r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;

        fcntl(fd, F_SETFL, O_NONBLOCK);

        int cr = connect(fd, r->ai_addr, r->ai_addrlen);
        if (cr < 0 && errno != EINPROGRESS) { close(fd); fd = -1; continue; }

        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        timeval tv{ timeout_sec, 0 };
        rc = select(fd + 1, nullptr, &wset, nullptr, &tv);
        if (rc <= 0) { close(fd); fd = -1; continue; }

        int err = 0; socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err) { close(fd); fd = -1; continue; }

        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
        set_keepalive(fd);
        break;
    }
    freeaddrinfo(res);

    if (fd < 0) throw std::runtime_error("Could not connect to " + host + ":" + port_str);
    return fd;
}

std::string peer_addr(int fd) {
    sockaddr_in6 addr{};
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
        return "unknown";

    char buf[INET6_ADDRSTRLEN] = {};
    // unwrap IPv4-mapped IPv6 (::ffff:x.x.x.x)
    if (IN6_IS_ADDR_V4MAPPED(&addr.sin6_addr)) {
        sockaddr_in v4{};
        v4.sin_family = AF_INET;
        std::memcpy(&v4.sin_addr, addr.sin6_addr.s6_addr + 12, 4);
        inet_ntop(AF_INET, &v4.sin_addr, buf, sizeof(buf));
    } else {
        inet_ntop(AF_INET6, &addr.sin6_addr, buf, sizeof(buf));
    }
    return std::string(buf) + ":" + std::to_string(ntohs(addr.sin6_port));
}

bool send_frame(int fd, const std::string& data) {
    uint32_t nlen = htonl(static_cast<uint32_t>(data.size()));
    if (!send_all(fd, reinterpret_cast<const char*>(&nlen), 4)) return false;
    if (!data.empty() && !send_all(fd, data.data(), data.size())) return false;
    return true;
}

bool recv_frame(int fd, std::string& out) {
    uint32_t nlen = 0;
    if (!recv_all(fd, reinterpret_cast<char*>(&nlen), 4)) return false;
    uint32_t len = ntohl(nlen);
    if (len == 0) { out.clear(); return true; }
    if (len > 64 * 1024) return false;
    out.resize(len);
    return recv_all(fd, out.data(), len);
}