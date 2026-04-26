#pragma once
#include <string>

// server socket listens on IPv6 with IPV6_V6ONLY=0
// so it accepts both IPv4 (mapped as ::ffff:x.x.x.x) and IPv6
int  create_server_socket(int port);
int  accept_client(int server_fd);

// resolves hostname via getaddrinfo — works with IPv4, IPv6, and domain names
int  connect_to_server(const std::string& host, int port, int timeout_sec = 10);

bool send_frame(int fd, const std::string& data);
bool recv_frame(int fd, std::string& out);

// returns printable address string of the connected peer
std::string peer_addr(int fd);