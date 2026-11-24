#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <time.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return 1; } } while (0)
static unsigned destroyed;
static void on_ctx_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                        int idx, long argl, void *argp) {
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    if (ptr == &destroyed) ++destroyed;
}
int main(void) {
    int idx = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, on_ctx_free);
    CHECK(idx >= 0);
    SSL_CTX *base = SSL_CTX_new(TLS_server_method());
    SSL_CTX *cached = SSL_CTX_new(TLS_server_method());
    CHECK(base && cached);
    CHECK(SSL_CTX_set_ex_data(cached, idx, &destroyed) == 1);
    SSL *a = SSL_new(base), *b = SSL_new(base);
    CHECK(a && b);
    CHECK(SSL_set_SSL_CTX(a, cached) == cached);
    CHECK(SSL_set_SSL_CTX(b, cached) == cached);
    SSL_CTX_free(cached);
    CHECK(destroyed == 0 && SSL_get_SSL_CTX(a) == cached && SSL_get_SSL_CTX(b) == cached);
    SSL_free(a);
    CHECK(destroyed == 0);
    SSL_free(b);
    CHECK(destroyed == 1);
    SSL_CTX_free(base);

    EVP_PKEY *key = EVP_RSA_gen(2048);
    X509 *cert = X509_new();
    CHECK(key && cert);
    CHECK(X509_set_version(cert, 2) && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1));
    CHECK(X509_gmtime_adj(X509_getm_notBefore(cert), 0) && X509_gmtime_adj(X509_getm_notAfter(cert), 3600));
    X509_NAME *name = X509_get_subject_name(cert);
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0));
    CHECK(X509_set_issuer_name(cert, name) && X509_set_pubkey(cert, key));
    CHECK(X509_sign(cert, key, EVP_sha256()) > 0);
    BIO *cert_pem = BIO_new(BIO_s_mem()), *key_pem = BIO_new(BIO_s_mem());
    CHECK(cert_pem && key_pem && PEM_write_bio_X509(cert_pem, cert));
    CHECK(PEM_write_bio_PrivateKey(key_pem, key, NULL, NULL, 0, NULL, NULL));
    char *cert_bytes, *key_bytes;
    long cert_len = BIO_get_mem_data(cert_pem, &cert_bytes), key_len = BIO_get_mem_data(key_pem, &key_bytes);
    CHECK(cert_len > 0 && key_len > 0);
    SSL_CTX *shared = SSL_CTX_new(TLS_server_method());
    CHECK(shared && SSL_CTX_use_certificate(shared, cert) && SSL_CTX_use_PrivateKey(shared, key));
    enum { iterations = 1000, rounds = 3 };
    double total[2] = {0};
    for (int round = 0; round < rounds; ++round) {
        for (int pass = 0; pass < 2; ++pass) {
            int reuse = (round + pass) % 2;
            clock_t start = clock();
            CHECK(start != (clock_t)-1);
            for (int i = 0; i < iterations; ++i) {
                SSL_CTX *ctx = reuse ? shared : SSL_CTX_new(TLS_server_method());
                CHECK(ctx);
                SSL *ssl = SSL_new(ctx);
                CHECK(ssl);
                if (!reuse) {
                    BIO *cb = BIO_new_mem_buf(cert_bytes, (int)cert_len), *kb = BIO_new_mem_buf(key_bytes, (int)key_len);
                    CHECK(cb && kb);
                    X509 *parsed_cert = PEM_read_bio_X509(cb, NULL, NULL, NULL);
                    EVP_PKEY *parsed_key = PEM_read_bio_PrivateKey(kb, NULL, NULL, NULL);
                    CHECK(parsed_cert && parsed_key && SSL_use_certificate(ssl, parsed_cert) && SSL_use_PrivateKey(ssl, parsed_key));
                    X509_free(parsed_cert); EVP_PKEY_free(parsed_key); BIO_free(cb); BIO_free(kb);
                }
                CHECK(SSL_check_private_key(ssl) && X509_cmp(SSL_get_certificate(ssl), cert) == 0);
                SSL_free(ssl);
                if (!reuse) SSL_CTX_free(ctx);
            }
            clock_t finish = clock();
            CHECK(finish != (clock_t)-1 && finish >= start);
            total[reuse] += (double)(finish - start) / CLOCKS_PER_SEC;
        }
    }
    printf("OpenSSL: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("CPU clock seconds for %d initializations each: new+PEM=%.6f shared=%.6f\n", iterations * rounds, total[0], total[1]);
    puts("PASS: context ownership and certificate identity; initialization-only microbenchmark, not a handshake or server benchmark");
    SSL_CTX_free(shared); BIO_free(cert_pem); BIO_free(key_pem); X509_free(cert); EVP_PKEY_free(key);
    return 0;
}
