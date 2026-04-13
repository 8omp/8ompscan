// include/scanner.h
#ifndef SCANNER_H
#define SCANNER_H

// TCP Connectスキャンを実行する関数
void scan_connect(char *ipaddr, int start_port, int end_port);

// TCP SYNスキャンを実行する関数
void syn_scan(char *dest_ipaddr, int start_port, int end_port);


#endif