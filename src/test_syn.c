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

int main(int argc, char *argv[]) {

    char source_ip[16] = "192.168.0.13";
    char dest_ip[16] = "192.168.0.1";

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
    // IPヘッダの長さは、IPヘッダのサイズを4バイト単位で表す必要があるため、5に設定。5にしているのは、定義が4bitで11までしか表せないから。
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
    tcph->source = htons(12340); // 任意の送信元ポート
    tcph->dest = htons(80); // 任意の宛先ポート
    tcph->seq = htonl(0);
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;// SYNフラグをセット
    tcph->window = htons(5840);
    tcph->check = 0;
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

    // 擬似ヘッダをコピー
    memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
    // TCPヘッダを擬似ヘッダの後ろにコピー
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    // 1バイト刻みから2バイト刻みに、sizeは32バイトのみ計算し、残りは計算しないようにする
    tcph->check = checksum((uint16_t *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

    // 通常のソケット通信では、IPヘッダはOS（カーネル）が自動で付け加える。
    // Raw Socketで自分でIPヘッダを作る場合は、
    // カーネルに二重でIPヘッダを付けられないように設定をする必要がある。
    // IPPROTO_IP：IP層の設定
    // IP_HDRINCL：1（true）に設定すると、自分でIPヘッダを作成して送ることを意味する
    // oneはただの有効(true)
    // setsockoptのoptvalはvoidポインタなので、値を直接渡せず
    // 値のアドレス（ポインタ）を渡す必要があるというCの関数仕様によるもの
    int one = 1;
    const int *val = &one;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
        perror("Error setting IP_HDRINCL");
        exit(1);
    }
    if(sendto(sock, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        perror("Error sending packet");
        exit(1);
    }else{
        printf("SYN packet sent successfully\n");
    }

    return 0;
}