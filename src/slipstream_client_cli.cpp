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

struct ClientArgs : MainArguments<ClientArgs> {
    using MainArguments<ClientArgs>::MainArguments;

    int listen_port = option("tcp-listen-port", 'l', "Listen port (default: 5201)") = 5201;
    std::vector<std::string> resolver = option("resolver", 'r', "Slipstream server resolver address (e.g., 1.1.1.1, 8.8.8.8:53, or [2001:db8::1]:53 for IPv6). Can be specified multiple times. (Required)");
    std::string congestion_control = option("congestion-control", 'c', "Congestion control algorithm (bbr, dcubic) (default: dcubic)") = "dcubic";
    bool gso = option('g', "GSO enabled (true/false) (default: false). Use --gso or --gso=true to enable.");
    std::string domain = option("domain", 'd', "Domain name used for the covert channel (Required)");
    int keep_alive_interval = option("keep-alive-interval", 't', "Send keep alive pings at this interval (default: 400, disabled: 0)") = 400;

    static std::string help(const std::string& program_name) {
        return "slipstream-client - A high-performance covert channel over DNS (client)\n\n" 
               "Usage: " + program_name + " [options]";
    }

    static const std::string version;
};

const std::string ClientArgs::version = "slipstream-client 0.1";

int main(int argc, char** argv) {
    int exit_code = 0;
    ClientArgs args(argc, argv);

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return 1;
    }
#endif

    // Ensure output buffers are flushed immediately (useful for debugging/logging)
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    /* Check mandatory client arguments */
    if (args.domain.empty()) {
        std::cerr << "Client error: Missing required --domain option" << std::endl;
        exit(1);
    }
    if (args.resolver.empty()) {
        std::cerr << "Client error: Missing required --resolver option (at least one required)" << std::endl;
        exit(1);
    }

    // Process resolver addresses
    std::vector<st_address_t> resolver_addresses;
    bool ipv4 = false;
    bool ipv6 = false;
    for (const auto& res_str : args.resolver) {
        st_address_t addr;
        ParsedEndpoint endpoint;
        std::string error;
        if (!parse_endpoint(res_str, 53, &endpoint, &error)) {
            std::cerr << "Invalid resolver address '" << res_str << "': " << error << std::endl;
            exit(1);
        }

        int is_name = 0;
        if (picoquic_get_server_address(endpoint.host.c_str(), endpoint.port, &addr.server_address, &is_name) != 0) {
            std::cerr << "Cannot resolve resolver address '" << endpoint.host << "' port " << endpoint.port << std::endl;
            exit(1);
        }

        if (addr.server_address.ss_family == AF_INET) {
            ipv4 = true;
        } else if (addr.server_address.ss_family == AF_INET6) {
            ipv6 = true;
        } else {
            std::cerr << "Resolver address has unsupported address family: " << res_str << std::endl;
            exit(1);
        }

        std::cerr << "Client resolver: " << res_str << " -> " << format_sockaddr(addr.server_address) << std::endl;
        resolver_addresses.push_back(addr);
    }

    if (ipv4 && ipv6) {
        // due to single param.local_af in slipstream_client.c
        std::cerr << "Cannot mix IPv4 and IPv6 resolver addresses" << std::endl;
        exit(1);
    }

    exit_code = picoquic_slipstream_client(
        args.listen_port,
        resolver_addresses.data(),
        resolver_addresses.size(),
        (char*)args.domain.c_str(),
        (char*)args.congestion_control.c_str(),
        args.gso,
        args.keep_alive_interval
    );

#ifdef _WINDOWS
    WSACleanup();
#endif

    exit(exit_code);
}
