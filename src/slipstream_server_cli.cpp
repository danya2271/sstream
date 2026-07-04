#include <iostream>
#include <string>
#include <vector>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <picosocks.h>
#include "slipstream.h"
#include "quick_arg_parser.hpp"

struct ParsedEndpoint {
    std::string host;
    int port;
};

static bool parse_port(const std::string& value, int* port) {
    if (value.empty()) {
        return false;
    }

    char* end = NULL;
    errno = 0;
    long parsed = strtol(value.c_str(), &end, 10);
    if (errno != 0 || *end != '\0' || parsed <= 0 || parsed > 65535) {
        return false;
    }

    *port = (int)parsed;
    return true;
}

static bool parse_endpoint(const std::string& value, int default_port,
                           ParsedEndpoint* endpoint, std::string* error) {
    if (value.empty()) {
        *error = "empty address";
        return false;
    }

    endpoint->port = default_port;

    if (value[0] == '[') {
        size_t closing = value.find(']');
        if (closing == std::string::npos) {
            *error = "missing closing bracket for IPv6 address";
            return false;
        }
        if (closing == 1) {
            *error = "empty IPv6 address";
            return false;
        }

        endpoint->host = value.substr(1, closing - 1);
        if (closing + 1 == value.size()) {
            return true;
        }
        if (value[closing + 1] != ':') {
            *error = "unexpected characters after IPv6 address";
            return false;
        }
        if (!parse_port(value.substr(closing + 2), &endpoint->port)) {
            *error = "invalid port";
            return false;
        }
        return true;
    }

    size_t first_colon = value.find(':');
    size_t last_colon = value.rfind(':');
    if (first_colon != std::string::npos && first_colon == last_colon) {
        endpoint->host = value.substr(0, first_colon);
        if (endpoint->host.empty()) {
            *error = "empty host";
            return false;
        }
        if (!parse_port(value.substr(first_colon + 1), &endpoint->port)) {
            *error = "invalid port";
            return false;
        }
        return true;
    }

    endpoint->host = value;
    return true;
}

static socklen_t sockaddr_len(const struct sockaddr_storage& addr) {
    if (addr.ss_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    }
    if (addr.ss_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return sizeof(struct sockaddr_storage);
}

static std::string format_sockaddr(const struct sockaddr_storage& addr) {
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    int ret = getnameinfo((const struct sockaddr*)&addr, sockaddr_len(addr),
                          host, sizeof(host), service, sizeof(service),
                          NI_NUMERICHOST | NI_NUMERICSERV);
    if (ret != 0) {
        return "unknown";
    }

    if (addr.ss_family == AF_INET6) {
        return "[" + std::string(host) + "]:" + std::string(service);
    }
    return std::string(host) + ":" + std::string(service);
}

struct ServerArgs : MainArguments<ServerArgs> {
    using MainArguments<ServerArgs>::MainArguments;

    int listen_port = option("dns-listen-port", 'l', "DNS listen port (default: 53)") = 53;
    int mtu = option("mtu", 'm', "Mtu size") = SLIPSTREAM_SERVER_MTU_MAX;
    std::string target_address = option("target-address", 'a', "Target server address (default: 127.0.0.1:5201)") = "127.0.0.1:5201";
    std::string cert = option("cert", 'c', "Certificate file path (default: certs/cert.pem)") = "certs/cert.pem";
    bool listen_ipv6 = option("dns-listen-ipv6", '6', "DNS listen on IPv6 (default: false)") = false;
    std::string key = option("key", 'k', "Private key file path (default: certs/key.pem)") = "certs/key.pem";
    std::string domain = option("domain", 'd', "Domain name this server is authoritative for (Required)");

    static std::string help(const std::string& program_name) {
        return "slipstream-server - A high-performance covert channel over DNS (server)\n\n" 
               "Usage: " + program_name + " [options]";
    }

    static const std::string version;
};

const std::string ServerArgs::version = "slipstream-server 0.1";

int main(int argc, char** argv) {
    int exit_code = 0;
    ServerArgs args(argc, argv);

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    // Ensure output buffers are flushed immediately
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check mandatory server arguments */
    if (args.domain.empty()) {
        std::cerr << "Server error: Missing required --domain option" << std::endl;
        exit(1);
    }

    // Process target address
    struct sockaddr_storage target_address;
    ParsedEndpoint endpoint;
    std::string error;
    if (!parse_endpoint(args.target_address, 5201, &endpoint, &error)) {
        std::cerr << "Invalid target address '" << args.target_address << "': " << error << std::endl;
        exit(1);
    }

    int is_name = 0;
    if (picoquic_get_server_address(endpoint.host.c_str(), endpoint.port, &target_address, &is_name) != 0) {
        std::cerr << "Cannot resolve target address '" << endpoint.host << "' port " << endpoint.port << std::endl;
        exit(1);
    }

    std::cerr << "Server target: " << args.target_address << " -> " << format_sockaddr(target_address) << std::endl;

    exit_code = picoquic_slipstream_server(
        args.listen_port,
        args.listen_ipv6,
        args.mtu,
        (char*)args.cert.c_str(),
        (char*)args.key.c_str(),
        &target_address,
        (char*)args.domain.c_str()
    );

#ifdef _WINDOWS
    WSACleanup();
#endif

    exit(exit_code);
}
