#include "socket_utils.h"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
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

int create_server_socket(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket() failed");

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(fd);
        throw std::runtime_error("bind() failed: " + std::string(strerror(errno)));
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        throw std::runtime_error("listen() failed");
    }
    return fd;
}

int accept_client(int server_fd) {
    sockaddr_in addr{};
    socklen_t   len = sizeof(addr);
    int fd = accept(server_fd, reinterpret_cast<sockaddr*>(&addr), &len);
    if (fd >= 0) set_keepalive(fd);
    return fd;
}

int connect_to_server(const std::string& ip, int port, int timeout_sec) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("socket() failed");

    fcntl(fd, F_SETFL, O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        throw std::runtime_error("Invalid IP address: " + ip);
    }

    int rc = connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        throw std::runtime_error("connect() failed: " + std::string(strerror(errno)));
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(fd, &wset);
    timeval tv{ timeout_sec, 0 };
    rc = select(fd + 1, nullptr, &wset, nullptr, &tv);
    if (rc <= 0) {
        close(fd);
        throw std::runtime_error(rc == 0 ? "Connection timed out" : "select() failed");
    }

    int err = 0; socklen_t elen = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err) {
        close(fd);
        throw std::runtime_error("connect error: " + std::string(strerror(err)));
    }

    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    set_keepalive(fd);
    return fd;
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