#include <stdio.h>
#include <stdlib.h>
#include "../include/banner.h"
#include "../include/scanner.h"

int main(int argc, char *argv[]){

    print_banner();
    if(argc != 4){
        fprintf(stderr, "Usage: %s <IP address> <start port> <end port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *dest_ipaddr = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    if(start_port < 1 || start_port > 65535 || end_port < 1 || end_port > 65535 || start_port > end_port){
        fprintf(stderr, "Invalid port range: %d - %d\n", start_port, end_port);
        exit(EXIT_FAILURE);
    }

    //scan_connect(dest_ipaddr, start_port, end_port);
    syn_scan(dest_ipaddr, start_port, end_port);

    return 0;
}