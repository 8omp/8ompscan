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
    unsigned long sum = 0;
    // 16ビット(毎に計算
    while( size > 1 ) {
        sum += *buf;
        buf++;
        size -= 2;
    }
    if( size == 1 ) { sum += *(uint8_t *)buf; }
    // 反転と溢れ処理
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

int main(int argc, char *argv[]) {

    char source_ip[16] = "";
    char dest_ip[16] = "";

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
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(dest_ip);

    // IPヘッダの設定
    iph->ihl = 5; // IPヘッダの長さ (5 * 4 = 20バイト)
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
    iph->check = checksum((uint16_t *)datagram, iph->ihl<<2);

    // TCPヘッダの設定

    


    return 0;
}