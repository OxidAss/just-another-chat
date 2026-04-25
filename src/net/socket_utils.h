#pragma once
#include <string>

int create_server_socket(int port);
int accept_client(int server_fd);
int connect_to_server(const std::string& ip, int port, int timeout_sec = 10);
bool send_frame(int fd, const std::string& data);
bool recv_frame(int fd, std::string& out);