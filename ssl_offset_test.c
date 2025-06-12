#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// 测试程序：验证OpenSSL 3.0.2中SSL结构体的内存布局
// 用于确定socket文件描述符在SSL和BIO结构体中的正确偏移量

void print_ssl_structure_info(SSL *ssl) {
    printf("=== SSL Structure Analysis ===\n");
    printf("SSL pointer: %p\n", ssl);
    
    // 获取BIO对象
    BIO *rbio = SSL_get_rbio(ssl);
    BIO *wbio = SSL_get_wbio(ssl);
    
    printf("Read BIO (rbio): %p\n", rbio);
    printf("Write BIO (wbio): %p\n", wbio);
    
    if (rbio) {
        // 尝试获取文件描述符
        int fd = -1;
        if (BIO_get_fd(rbio, &fd) > 0) {
            printf("Socket FD from BIO_get_fd: %d\n", fd);
        } else {
            printf("Failed to get FD from BIO\n");
        }
        
        // 分析BIO结构体的内存布局
        printf("\n=== BIO Structure Memory Analysis ===\n");
        printf("BIO pointer: %p\n", rbio);
        
        // 尝试从不同偏移量读取可能的文件描述符
        for (int offset = 0; offset < 0x100; offset += 8) {
            int *ptr = (int*)((char*)rbio + offset);
            int value = *ptr;
            
            // 检查是否可能是文件描述符（通常是小的正整数）
            if (value > 0 && value < 65536) {
                printf("Offset 0x%02x: %d (possible FD)\n", offset, value);
            }
        }
    }
    
    // 分析SSL结构体的内存布局
    printf("\n=== SSL Structure Memory Analysis ===\n");
    
    // 计算rbio在SSL结构体中的偏移量
    if (rbio) {
        for (int offset = 0; offset < 0x200; offset += 8) {
            void **ptr = (void**)((char*)ssl + offset);
            if (*ptr == rbio) {
                printf("rbio found at SSL offset 0x%02x\n", offset);
                break;
            }
        }
    }
    
    // 搜索SSL结构体中可能的socket文件描述符
    printf("\n=== Searching for Socket FD in SSL structure ===\n");
    for (int offset = 0; offset < 0x300; offset += 4) {
        int *ptr = (int*)((char*)ssl + offset);
        int value = *ptr;
        
        // 检查是否可能是文件描述符
        if (value > 0 && value < 65536) {
            printf("SSL offset 0x%03x: %d (possible FD)\n", offset, value);
        }
    }
}

int main() {
    // 初始化OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("OpenSSL version number: 0x%lx\n", OpenSSL_version_num());
    
    // 创建SSL上下文
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }
    
    // 创建socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        SSL_CTX_free(ctx);
        return 1;
    }
    
    printf("\nCreated socket FD: %d\n", sockfd);
    
    // 创建SSL对象
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // 将socket与SSL关联
    if (SSL_set_fd(ssl, sockfd) != 1) {
        fprintf(stderr, "Failed to set SSL file descriptor\n");
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    printf("\nSSL object created and associated with socket FD %d\n", sockfd);
    
    // 分析SSL结构体
    print_ssl_structure_info(ssl);
    
    // 清理资源
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    
    return 0;
}