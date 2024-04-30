#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "cnds.constructor.university"
#define PORT "443"

int main() {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    X509 *cert;
    long verify_result;
    int ret;

    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // Create SSL context
    const SSL_METHOD *method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        fprintf(stderr, "Failed to create SSL context\n");
        return 1;
    }

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // Load default system trust store
    if (!SSL_CTX_set_default_verify_paths(ctx)) {
        fprintf(stderr, "Failed to load default trust store\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Failed to create SSL object\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    // Connect to the server
    bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, HOST ":" PORT);
    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Failed to connect to the server\n");
        BIO_free_all(bio);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Get the server's certificate
    BIO_get_ssl(bio, &ssl);
    cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "No server certificate received\n");
        BIO_free_all(bio);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Verify the server's certificate
    verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        fprintf(stderr, "Certificate verification failed: %s\n", X509_verify_cert_error_string(verify_result));
        X509_free(cert);
        BIO_free_all(bio);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Check the certificate name
    ret = X509_check_host(cert, HOST, strlen(HOST), 0, NULL);
    if (ret <= 0) {
        fprintf(stderr, "Certificate name does not match the expected host\n");
        X509_free(cert);
        BIO_free_all(bio);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Check the certificate expiration date
    if (X509_cmp_current_time(X509_get_notBefore(cert)) >= 0 || X509_cmp_current_time(X509_get_notAfter(cert)) <= 0) {
        fprintf(stderr, "Certificate is expired or not yet valid\n");
        X509_free(cert);
        BIO_free_all(bio);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Check the certificate revocation status (using OCSP)
	//still need to do

    printf("TLS connection established successfully\n");

    // Gracefully close the connection
    BIO_free_all(bio);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    X509_free(cert);

    return 0;
}
