#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>

#define PS_CONNECT 0   /* ポートに接続できた場合 */
#define PS_NOCONNECT 1 /* ポートに接続できなかった場合 */
#define PS_ERROR -1     /* 接続エラー */

// タイムアウトを設定したソケットを作成する
static int create_timeout_socket(){

    int sock = 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        perror("socket");
        return -1;
    }

    //送信タイムアウト設定
    struct timeval send_tv;
    send_tv.tv_sec = 3;
    send_tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_tv, sizeof(send_tv));  

    //受信タイムアウト設定
    struct timeval recv_tv;
    recv_tv.tv_sec = 3;
    recv_tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));

    return sock;

}

// 指定ポートに接続を試みる

// dest.sin_family: IPv4
// dest.sin_port: ポート番号
// dest.sin_addr: 接続先のIPアドレス
static int connect_to_port(char *ipaddr, int n_port){

    struct sockaddr_in dest;
    int sock = 0;
    int rc = 0;
    int ret_code = 0;

    sock = create_timeout_socket();
    if(sock < 0){
        return PS_ERROR;
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(n_port);

    if (inet_pton(AF_INET, ipaddr, &dest.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ipaddr);
        close(sock);
        return PS_ERROR;
    }

    errno = 0;
    rc = connect(sock, (struct sockaddr*)&dest, sizeof(dest));
    
    if(rc == 0){
        ret_code = PS_CONNECT;
    }else if(errno == ECONNREFUSED || errno == ETIMEDOUT || errno == EINPROGRESS){
        ret_code = PS_NOCONNECT;
    }else{
        perror("connect");
        ret_code = PS_ERROR;
    }

    close(sock);
    return ret_code;

}

//ポート番号に対応するサービス名を出力する
static void print_portname(int port_num){

    struct sockaddr_in sa;
    char service[32];

    memset(&sa, 0, sizeof(sa));
    memset(service, 0, sizeof(service));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port_num);

    int err = getnameinfo((struct sockaddr*)&sa, sizeof(sa), NULL, 0, service, sizeof(service), 0);

    if(err == 0){
        fprintf(stdout, "Port %d: Open (%s)\n", port_num, service);
    }else{
        fprintf(stdout, "Port %d: Open (unknown)\n", port_num);
    }

}

//ポートスキャンの実行
static void port_scan(char *ipaddr, int start_port, int end_port){

    int port_num = 0;
    int rc = 0;

    for(port_num = start_port; port_num <= end_port; port_num++){
        rc = connect_to_port(ipaddr, port_num);

        // if(rc == PS_ERROR){
        //     fprintf(stderr, "Error occurred while connecting to port %d\n", port_num);
        //     exit(EXIT_FAILURE);
        // }

        if(rc == PS_CONNECT){
            print_portname(port_num);
        }
    }

}

int main(int argc, char *argv[]){

    if(argc != 4){
        fprintf(stderr, "Usage: %s <IP address> <start port> <end port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *ipaddr = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    if(start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port){
        fprintf(stderr, "Invalid port range: %d - %d\n", start_port, end_port);
        exit(EXIT_FAILURE);
    }

    port_scan(ipaddr, start_port, end_port);

    return 0;
}