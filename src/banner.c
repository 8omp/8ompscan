// src/banner.c
#include <stdio.h>
#include "banner.h"

// ANSIエスケープコードによる色定義
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_RESET   "\033[0m"

void print_banner(void){
    printf("%s", COLOR_CYAN);
    printf("\n");
    printf("  ████████   \n");
    printf(" ███▒▒▒▒███   \n");
    printf("▒███   ▒███   ██████  █████████████   ████████      █████   ██████   ██████   ████████  \n");
    printf("▒▒████████   ███▒▒███▒▒███▒▒███▒▒███ ▒▒███▒▒███    ███▒▒   ███▒▒███ ▒▒▒▒▒███ ▒▒███▒▒███ \n");
    printf(" ███▒▒▒▒███ ▒███ ▒███ ▒███ ▒███ ▒███  ▒███ ▒███   ▒▒█████ ▒███ ▒▒▒   ███████  ▒███ ▒███ \n");
    printf("▒███   ▒███ ▒███ ▒███ ▒███ ▒███ ▒███  ▒███ ▒███    ▒▒▒▒███▒███  ███ ███▒▒███  ▒███ ▒███ \n");
    printf("▒▒████████  ▒▒██████  █████▒███ █████ ▒███████     ██████ ▒▒██████ ▒▒████████ ████ █████\n");
    printf(" ▒▒▒▒▒▒▒▒    ▒▒▒▒▒▒  ▒▒▒▒▒ ▒▒▒ ▒▒▒▒▒  ▒███▒▒▒     ▒▒▒▒▒▒   ▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒ ▒▒▒▒ ▒▒▒▒▒ \n");
    printf("                                      ▒███                                              \n");
    printf("                                      █████                                             \n");
    printf("                                     ▒▒▒▒▒                                              \n");
    printf("%s", COLOR_RESET); // 色をリセット

    // Authorとツール情報を出力
    printf("\n");
    printf("==========================================================\n");
    printf("%s[*] Author: 8omp%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s[*] Version : 1.0.0%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s[*] Github  : https://github.com/8omp/C_port-scanner%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s[!] WARNING : For educational and authorized testing only.%s\n", COLOR_RED, COLOR_RESET);
    printf("==========================================================\n\n");
}