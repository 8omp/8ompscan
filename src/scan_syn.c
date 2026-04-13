#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>   // IPヘッダ用
#include <netinet/tcp.h>  // TCPヘッダ用
#include <arpa/inet.h>
#include <netinet/in.h>

//チェックサム計算
uint16_t checksum(uint16_t *buf, int size) {
    uint32_t sum = 0;
    // 16ビット(2バイト)毎に計算
    while( size > 1 ) {
        sum += *buf;
        buf++;
        size -= 2;
    }
    if( size == 1 ) { sum += *(uint8_t *)buf; }
    // 溢れ処理
    sum = (sum & 0xffff) + (sum >> 16);
    sum = sum + (sum >> 16);
    // ビット反転
    return ~sum;
}

void syn_scan(char *dest_ipaddr, int start_port, int end_port) {

    char source_ip[16] = "127.0.0.1";
    char *dest_ip = dest_ipaddr;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock < 0){
        perror("Socket error");
        exit(1);
    }

    char datagram[4096];
    memset(datagram, 0, 4096);

    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);//これは別に必要ない
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    // IPヘッダの設定
    iph->ihl = 5; // IPヘッダの長さ (5 * 4 = 20バイト)4倍は<<2で後に計算する
    iph->version = 4;
    iph->tos = 0;// Type of Service, 通常は0でいいっぽい
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(9999);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;// TCPプロトコル
    iph->check = 0;
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    // IPヘッダのチェックサム計算
    iph->check = checksum((uint16_t *)datagram, iph->ihl<<2);// <<2は4倍するため

    // TCPヘッダの設定
    tcph->source = htons(12345); // 任意の送信元ポート
    tcph->seq = htonl(0);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;// SYNフラグをセット
    tcph->window = htons(5840);
    tcph->urg_ptr = 0;

    //12バイト
    struct pseudo_header{
        uint32_t source_addr;
        uint32_t dest_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    char pseudo_packet[4096];//4096バイト
    struct pseudo_header psh;

    psh.source_addr = inet_addr(source_ip);
    psh.dest_addr = sin.sin_addr.s_addr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));

    int one = 1;
    const int *val = &one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
        perror("Error setting IP_HDRINCL");
        exit(1);
    }

    for(int port = start_port; port <= end_port; port++){
        tcph->dest = htons(port);
        tcph->check = 0;

        memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

        tcph->check = checksum((uint16_t *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

        if(sendto(sock, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
            perror("Error sending packet");
            exit(1);
        }else{
            printf("SYN packet sent successfully\n");
        }
    }

    close(sock);
}