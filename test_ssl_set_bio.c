#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

int main() {
    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    
    // 创建 SSL 上下文
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        printf("Failed to create SSL context\n");
        return 1;
    }
    
    // 创建 SSL 对象
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        printf("Failed to create SSL object\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    
    // 创建 socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("Failed to create socket\n");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }
    
    printf("Created socket FD: %d\n", sockfd);
    
    // 测试不同类型的 BIO
    printf("\n=== Testing different BIO types ===\n");
    
    // 1. 测试文件描述符 BIO (BIO_s_fd)
    printf("\n1. Testing BIO_s_fd:\n");
    BIO *fd_bio = BIO_new(BIO_s_fd());
    if (fd_bio) {
        BIO_set_fd(fd_bio, sockfd, BIO_NOCLOSE);
        printf("Created fd_bio, setting to SSL...\n");
        SSL_set_bio(ssl, fd_bio, fd_bio);  // 这里会触发我们的探针
        printf("SSL_set_bio completed for fd_bio\n");
        
        // 验证文件描述符
        int retrieved_fd = BIO_get_fd(fd_bio, NULL);
        printf("Retrieved FD from BIO: %d\n", retrieved_fd);
    }
    
    // 2. 测试 socket BIO (BIO_s_socket)
    printf("\n2. Testing BIO_s_socket:\n");
    BIO *socket_bio = BIO_new(BIO_s_socket());
    if (socket_bio) {
        BIO_set_fd(socket_bio, sockfd, BIO_NOCLOSE);
        printf("Created socket_bio, setting to SSL...\n");
        SSL_set_bio(ssl, socket_bio, socket_bio);  // 这里会触发我们的探针
        printf("SSL_set_bio completed for socket_bio\n");
        
        // 验证文件描述符
        int retrieved_fd = BIO_get_fd(socket_bio, NULL);
        printf("Retrieved FD from socket BIO: %d\n", retrieved_fd);
    }
    
    // 3. 测试内存 BIO (BIO_s_mem) - 这个不应该有文件描述符
    printf("\n3. Testing BIO_s_mem (should not have FD):\n");
    BIO *mem_bio = BIO_new(BIO_s_mem());
    if (mem_bio) {
        printf("Created mem_bio, setting to SSL...\n");
        SSL_set_bio(ssl, mem_bio, mem_bio);  // 这里会触发我们的探针
        printf("SSL_set_bio completed for mem_bio\n");
        
        // 尝试获取文件描述符（应该失败）
        int retrieved_fd = BIO_get_fd(mem_bio, NULL);
        printf("Retrieved FD from mem BIO: %d (should be -1)\n", retrieved_fd);
    }
    
    printf("\n=== Test completed ===\n");
    
    // 清理资源
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    return 0;
}