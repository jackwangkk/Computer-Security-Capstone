#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <time.h>

#define MAX_DEVICES 256

typedef struct {
    char ip[INET_ADDRSTRLEN];
    unsigned char mac[6];
} Device;

Device devices[MAX_DEVICES];
int device_count = 0;

void send_arp_request(int sock, const char *interface, const char *target_ip) {
    struct ifreq ifr;
    struct sockaddr_ll device;
    unsigned char buffer[42]; // ARP packet size

    // Get the MAC address of the interface
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        exit(EXIT_FAILURE);
    }
    unsigned char *src_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    // Get the IP address of the interface
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR)");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in *src_ip = (struct sockaddr_in *)&ifr.ifr_addr;

    // Get the interface index
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl(SIOCGIFINDEX)");
        exit(EXIT_FAILURE);
    }
    device.sll_ifindex = ifr.ifr_ifindex;
    device.sll_halen = ETH_ALEN;

    // Broadcast MAC address
    memset(device.sll_addr, 0xff, ETH_ALEN);

    // Construct ARP request
    struct ether_header *eth_hdr = (struct ether_header *)buffer;
    struct ether_arp *arp_hdr = (struct ether_arp *)(buffer + ETH_HLEN);

    // Ethernet header
    memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN); // Broadcast
    memcpy(eth_hdr->ether_shost, src_mac, ETH_ALEN);
    eth_hdr->ether_type = htons(ETH_P_ARP);

    // ARP header
    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr->ea_hdr.ar_hln = ETH_ALEN;
    arp_hdr->ea_hdr.ar_pln = 4;
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);
    memcpy(arp_hdr->arp_sha, src_mac, ETH_ALEN); // Sender MAC
    memcpy(arp_hdr->arp_spa, &src_ip->sin_addr, 4); // Sender IP
    memset(arp_hdr->arp_tha, 0x00, ETH_ALEN); // Target MAC
    inet_pton(AF_INET, target_ip, arp_hdr->arp_tpa); // Target IP

    // Send the ARP request
    if (sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&device, sizeof(device)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }
}

void receive_arp_reply(int sock) {
    unsigned char buffer[42];
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    int timeout = 1; // 設定超時時間為 5 秒
    time_t start_time = time(NULL);

    while (time(NULL) - start_time < timeout) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&addr, &addr_len);
        if (len < 0) {
            perror("recvfrom");
            continue; // 如果沒有資料，繼續等待
        }

        struct ether_header *eth_hdr = (struct ether_header *)buffer;
        if (ntohs(eth_hdr->ether_type) == ETH_P_ARP) {
            struct ether_arp *arp_hdr = (struct ether_arp *)(buffer + ETH_HLEN);
            if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
                char sender_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip, sizeof(sender_ip));

                // 儲存設備資訊
                strcpy(devices[device_count].ip, sender_ip);
                memcpy(devices[device_count].mac, arp_hdr->arp_sha, 6);
                device_count++;

                if (device_count >= MAX_DEVICES) {
                    break;
                }
            }
        }
    }
}

void print_devices() {
    printf("Available devices\n");
    printf("Index | IP           | MAC\n");
    printf("-----------------------------\n");
    for (int i = 0; i < device_count; i++) {
        printf("%5d | %-12s | %02x:%02x:%02x:%02x:%02x:%02x\n",
               i,
               devices[i].ip,
               devices[i].mac[0], devices[i].mac[1], devices[i].mac[2],
               devices[i].mac[3], devices[i].mac[4], devices[i].mac[5]);
    }
    printf("-----------------------------\n");
}

int main() {
    const char *interface = "enp0s3"; // 替換為您的網路介面名稱
    const char *subnet = "10.0.2.";  // 替換為您的子網路前綴

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // 遍歷子網路中的所有 IP
    for (int i = 1; i <= 254; i++) {
        char target_ip[INET_ADDRSTRLEN];
        snprintf(target_ip, sizeof(target_ip), "%s%d", subnet, i);
        send_arp_request(sock, interface, target_ip);
        usleep(1000); // 等待 10 毫秒，避免過多請求
    }

    printf("Listening for ARP replies...\n");
    receive_arp_reply(sock);

    print_devices();

    // 選擇目標和網關
    int victim_index, gateway_index;
    printf("Select Victim IP index: ");
    scanf("%d", &victim_index);
    printf("Select Gateway IP index: ");
    scanf("%d", &gateway_index);

    printf("Victim IP: %s, Gateway IP: %s\n",
           devices[victim_index].ip, devices[gateway_index].ip);

    close(sock);
    return 0;
}