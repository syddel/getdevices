#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using Clock = std::chrono::steady_clock;

struct Network {
    std::string interface;
    uint32_t ip = 0;       // Host byte order
    uint32_t mask = 0;     // Host byte order
    std::array<uint8_t, 6> mac{};
};

struct Device {
    uint32_t ip = 0;       // Host byte order
    std::array<uint8_t, 6> mac{};
    std::string hostname = "-";
};

static std::string ipString(uint32_t ip) {
    in_addr addr{};
    addr.s_addr = htonl(ip);

    char text[INET_ADDRSTRLEN]{};
    if (!inet_ntop(AF_INET, &addr, text, sizeof(text)))
        return "?";

    return text;
}

static std::string macString(const std::array<uint8_t, 6>& mac) {
    char text[18];

    std::snprintf(
        text, sizeof(text),
                  "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2],
                  mac[3], mac[4], mac[5]);

    return text;
}

// Find an active, non-loopback IPv4 interface and its MAC address.
static bool getNetwork(Network& net) {
    ifaddrs* interfaces = nullptr;

    if (getifaddrs(&interfaces) != 0)
        return false;

    bool found = false;

    for (ifaddrs* it = interfaces; it; it = it->ifa_next) {
        if (!it->ifa_addr || !it->ifa_netmask)
            continue;

        if (it->ifa_addr->sa_family != AF_INET)
            continue;

        if (!(it->ifa_flags & IFF_UP) ||
            !(it->ifa_flags & IFF_RUNNING) ||
            (it->ifa_flags & IFF_LOOPBACK))
            continue;

        auto* addr = reinterpret_cast<sockaddr_in*>(it->ifa_addr);
        auto* mask = reinterpret_cast<sockaddr_in*>(it->ifa_netmask);

        uint32_t ip = ntohl(addr->sin_addr.s_addr);
        uint32_t netmask = ntohl(mask->sin_addr.s_addr);

        if (ip == 0 || netmask == 0)
            continue;

        // ARP scanning requires an Ethernet-like interface.
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
            continue;

        ifreq req{};
        std::strncpy(req.ifr_name, it->ifa_name, IFNAMSIZ - 1);

        if (ioctl(fd, SIOCGIFHWADDR, &req) != 0 || req.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
            close(fd);
            continue;
        }

        std::array<uint8_t, 6> mac{};
        std::memcpy(mac.data(), req.ifr_hwaddr.sa_data, mac.size());
        close(fd);

        net.interface = it->ifa_name;
        net.ip = ip;
        net.mask = netmask;
        net.mac = mac;

        found = true;
        break;
    }

    freeifaddrs(interfaces);
    return found;
}

static bool isValidMask(uint32_t mask) {
    // A contiguous IPv4 mask has the form 111...1100...00.
    uint32_t inverse = ~mask;
    return (inverse & (inverse + 1)) == 0;
}

static bool sendArpRequest(int fd, int ifindex, const Network& net, uint32_t targetIP)
{
    struct Packet {
        ethhdr ethernet;
        arphdr arp;
        uint8_t senderMac[6];
        uint8_t senderIP[4];
        uint8_t targetMac[6];
        uint8_t targetIP[4];
    } __attribute__((packed)) packet{};

    std::memset(packet.ethernet.h_dest, 0xff, ETH_ALEN);
    std::memcpy(packet.ethernet.h_source, net.mac.data(), ETH_ALEN);
    packet.ethernet.h_proto = htons(ETH_P_ARP);

    packet.arp.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ar_pro = htons(ETH_P_IP);
    packet.arp.ar_hln = ETH_ALEN;
    packet.arp.ar_pln = 4;
    packet.arp.ar_op = htons(ARPOP_REQUEST);

    std::memcpy(packet.senderMac, net.mac.data(), 6);

    uint32_t senderIP = htonl(net.ip);
    uint32_t destIP = htonl(targetIP);

    std::memcpy(packet.senderIP, &senderIP, 4);
    std::memset(packet.targetMac, 0, 6);
    std::memcpy(packet.targetIP, &destIP, 4);

    sockaddr_ll destination{};
    destination.sll_family = AF_PACKET;
    destination.sll_protocol = htons(ETH_P_ARP);
    destination.sll_ifindex = ifindex;
    destination.sll_halen = ETH_ALEN;
    std::memset(destination.sll_addr, 0xff, ETH_ALEN);

    ssize_t sent = sendto(
        fd, &packet, sizeof(packet), 0,
                          reinterpret_cast<sockaddr*>(&destination),
                          sizeof(destination));

    return sent == sizeof(packet);
}

static bool receiveArpReply(int fd, const Network& net, Device& device)
{
    // A little extra room for the Ethernet header and VLAN tags.
    uint8_t buffer[2048];

    sockaddr_ll source{};
    socklen_t sourceLen = sizeof(source);

    ssize_t length = recvfrom(
        fd, buffer, sizeof(buffer), MSG_DONTWAIT,
                              reinterpret_cast<sockaddr*>(&source), &sourceLen);

    if (length < 0)
        return false;

    if (source.sll_pkttype == PACKET_OUTGOING ||
        length < static_cast<ssize_t>(
            sizeof(ethhdr) + sizeof(arphdr) + 20))
        return false;

    auto* eth = reinterpret_cast<const ethhdr*>(buffer);

    if (ntohs(eth->h_proto) != ETH_P_ARP)
        return false;

    auto* arp = reinterpret_cast<const arphdr*>(
        buffer + sizeof(ethhdr));

    if (ntohs(arp->ar_hrd) != ARPHRD_ETHER ||
        ntohs(arp->ar_pro) != ETH_P_IP ||
        arp->ar_hln != 6 ||
        arp->ar_pln != 4 ||
        ntohs(arp->ar_op) != ARPOP_REPLY)
        return false;

    const uint8_t* senderMac = buffer + sizeof(ethhdr) + sizeof(arphdr);
    const uint8_t* senderIP = senderMac + 6;
    const uint8_t* targetIP = senderIP + 6 + 4;

    uint32_t sender = 0;
    uint32_t target = 0;

    std::memcpy(&sender, senderIP, 4);
    std::memcpy(&target, targetIP, 4);

    sender = ntohl(sender);
    target = ntohl(target);

    // Accept replies addressed to our local IP, including replies
    // whose sender IP matches our own IP.
    if (target != net.ip || sender == 0)
        return false;

    device.ip = sender;
    std::memcpy(device.mac.data(), senderMac, 6);

    return true;
}

static std::vector<Device> scanNetwork(const Network& net) {
    std::vector<Device> devices;

    const uint32_t network = net.ip & net.mask;
    const uint32_t broadcast = network | ~net.mask;

    if (!isValidMask(net.mask) ||
        broadcast <= network + 1 ||
        static_cast<uint64_t>(broadcast) - network - 1 > 65534) {
        std::cerr << "Invalid subnet or subnet too large.\n";
    return devices;
        }

        const uint64_t total = static_cast<uint64_t>(broadcast) - network - 1;

        int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

        if (fd < 0) {
            std::cerr << "Cannot open raw packet socket: "
            << std::strerror(errno)
            << "\nRun as root or grant CAP_NET_RAW.\n";
            return devices;
        }

        unsigned int ifindex = if_nametoindex(net.interface.c_str());

        if (ifindex == 0) {
            std::cerr << "Cannot find interface index.\n";
            close(fd);
            return devices;
        }

        sockaddr_ll bindAddress{};
        bindAddress.sll_family = AF_PACKET;
        bindAddress.sll_protocol = htons(ETH_P_ARP);
        bindAddress.sll_ifindex = static_cast<int>(ifindex);

        if (bind(fd, reinterpret_cast<sockaddr*>(&bindAddress), sizeof(bindAddress)) != 0) {
            std::cerr << "Cannot bind packet socket: " << std::strerror(errno) << '\n';
            close(fd);
            return devices;
        }

        std::cout << "Scanning " << ipString(network)
        << " through " << ipString(broadcast)
        << " on " << net.interface
        << " (" << total << " addresses)...\n";

        // Map IP to index so repeated ARP replies don't duplicate devices.
        std::vector<int64_t> seen(static_cast<size_t>(total), -1);

        std::vector<Device> results;
        results.reserve(256);

        auto processReplies = [&]() {
            for (;;) {
                Device d;

                if (!receiveArpReply(fd, net, d))
                    break;

                if (d.ip <= network || d.ip >= broadcast)
                    continue;

                size_t index = static_cast<size_t>(
                    static_cast<uint64_t>(d.ip) - network - 1);

                if (index >= seen.size())
                    continue;

                if (seen[index] >= 0)
                    continue;

                seen[index] = static_cast<int64_t>(results.size());
                results.push_back(d);

                std::cout << std::left
                << std::setw(16) << ipString(d.ip)
                << macString(d.mac) << '\n'
                << std::flush;
            }
        };

        // Send in batches while draining responses between batches.
        // This avoids creating processes and avoids a huge packet burst.
        constexpr uint64_t BATCH_SIZE = 64;

        for (uint64_t offset = 0; offset < total;
             offset += BATCH_SIZE) {

            uint64_t end = std::min(total, offset + BATCH_SIZE);

        for (uint64_t i = offset; i < end; ++i) {
            uint32_t target = static_cast<uint32_t>(static_cast<uint64_t>(network) + 1 + i);

            // Do not skip our own IP.
            sendArpRequest(fd, static_cast<int>(ifindex), net, target);
        }

        // Briefly wait for replies to this batch.
        auto deadline = Clock::now() + std::chrono::milliseconds(10);

        do {
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;

            int rc = poll(&pfd, 1, 2);

            if (rc > 0 && (pfd.revents & POLLIN))
                processReplies();

        } while (Clock::now() < deadline);
             }

             // Collect late replies after the last batch.
             auto deadline = Clock::now() + std::chrono::milliseconds(800);

             while (Clock::now() < deadline) {
                 pollfd pfd{};
                 pfd.fd = fd;
                 pfd.events = POLLIN;

                 int remaining = static_cast<int>(
                     std::chrono::duration_cast<std::chrono::milliseconds>(
                         deadline - Clock::now()).count());

                 int rc = poll(&pfd, 1, std::min(remaining, 50));

                 if (rc > 0 && (pfd.revents & POLLIN))
                     processReplies();
             }

             close(fd);
             devices = std::move(results);

             return devices;
}

static void resolveHostnames(std::vector<Device>& devices) {
    if (devices.empty())
        return;

    // Reverse DNS can be slow, so resolve several names concurrently.
    std::atomic<size_t> next{0};

    unsigned int workerCount = std::min(8u, std::max(1u, std::thread::hardware_concurrency()));

    std::vector<std::thread> workers;

    for (unsigned int w = 0; w < workerCount; ++w) {
        workers.emplace_back([&]() {
            for (;;) {
                size_t i = next.fetch_add(1);

                if (i >= devices.size())
                    break;

                sockaddr_in addr{};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = htonl(devices[i].ip);

                char hostname[NI_MAXHOST]{};

                int rc = getnameinfo(
                    reinterpret_cast<sockaddr*>(&addr),
                                     sizeof(addr),
                                     hostname, sizeof(hostname),
                                     nullptr, 0,
                                     NI_NAMEREQD);

                if (rc == 0)
                    devices[i].hostname = hostname;
            }
        });
    }

    for (auto& worker : workers)
        worker.join();
}

int main() {
    Network net;

    if (!getNetwork(net)) {
        std::cerr << "No suitable active Ethernet IPv4 interface found.\n";
        return 1;
    }

    std::cout << "Using interface: " << net.interface
    << " (" << ipString(net.ip) << ")"
    << ", MAC " << macString(net.mac) << '\n';

    auto devices = scanNetwork(net);

    // Ensure the originating machine is included in the results.
    auto self = std::find_if(
        devices.begin(), devices.end(),
                             [&](const Device& d) {
                                 return d.ip == net.ip;
                             });

    if (self == devices.end()) {
        Device localDevice;
        localDevice.ip = net.ip;
        localDevice.mac = net.mac;
        devices.push_back(localDevice);
    }

    std::cout << "\nResolving hostnames...\n";
    resolveHostnames(devices);

    std::sort(devices.begin(), devices.end(),
              [](const Device& a, const Device& b) {
                  return a.ip < b.ip;
              });

    std::cout << "\nFinal results:\n"
    << std::left
    << std::setw(16) << "IP address"
    << "Hostname\n";

    for (const auto& d : devices) {
        std::cout << std::left
        << std::setw(16) << ipString(d.ip)
        << d.hostname << '\n';
    }

    std::cout << "\nFound " << devices.size() << " responding devices.\n";

    return 0;
}

