#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "test_common.h"

int TestSha256_1()
{
    int fd = -1;
    SHA256_CTX sha256_ctx;
    uint8_t sha256_data[SHA256_DIGEST_LENGTH] = { 0 };
    int ret = -1;

    do {
        fd = open("../test.bin", O_RDONLY);
        if (fd == -1) {
            TEST_LOG("open fail, errno: %d, %s", errno, strerror(errno));
            break;
        }

        int result = SHA256_Init(&sha256_ctx);
        if (result != 1) {
            TEST_LOG("SHA256_Init fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
            break;
        }

        int read_len = -1;
        uint8_t buffer[1024] = { 0 };
        do {
            read_len = read(fd, buffer, sizeof(buffer));
            if (read_len == -1) {
                TEST_LOG("read fail, errno: %d, %s", errno, strerror(errno));
                break;
            }
            if (read_len == 0) {
                TEST_LOG("read successful!");
                break;
            }
            result = SHA256_Update(&sha256_ctx, buffer, read_len);
            if (result != 1) {
                TEST_LOG("SHA256_Update fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
                read_len = -1;
                break;
            }
        } while (1);

        if (read_len != 0) {
            TEST_LOG("read fail!");
            break;
        }

        result = SHA256_Final(sha256_data, &sha256_ctx);
        if (result != 1) {
            TEST_LOG("SHA256_Final fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
            break;
        }

        TEST_LOG("sha256:");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x ", sha256_data[i]);
        }
        printf("\n");

        ret = 0;
    } while (0);

    if (fd != -1) {
        close(fd);
        fd = -1;
    }

    return ret;
}

int TestSha256_2()
{
    int fd = -1;
    EVP_MD_CTX* evp_md_ctx = NULL;
    uint8_t sha256_data[SHA256_DIGEST_LENGTH] = { 0 };
    int ret = -1;

    do {
        fd = open("../test.bin", O_RDONLY);
        if (fd == -1) {
            TEST_LOG("open fail, errno: %d, %s", errno, strerror(errno));
            break;
        }

        evp_md_ctx = EVP_MD_CTX_new();
        if (evp_md_ctx == NULL) {
            TEST_LOG("EVP_MD_CTX_new fail!");
            break;
        }

        int result = EVP_DigestInit_ex(evp_md_ctx, EVP_sha256(), NULL);
        if (result != 1) {
            TEST_LOG("EVP_DigestInit_ex fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
            break;
        }

        int read_len = -1;
        uint8_t buffer[1024] = { 0 };
        do {
            read_len = read(fd, buffer, sizeof(buffer));
            if (read_len == -1) {
                TEST_LOG("read fail, errno: %d, %s", errno, strerror(errno));
                break;
            }
            if (read_len == 0) {
                TEST_LOG("read successful!");
                break;
            }
            result = EVP_DigestUpdate(evp_md_ctx, buffer, read_len);
            if (result != 1) {
                TEST_LOG("EVP_DigestUpdate fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
                read_len = -1;
                break;
            }
        } while (1);

        if (read_len != 0) {
            TEST_LOG("read fail!");
            break;
        }

        uint32_t sha256_data_len = 0;
        result = EVP_DigestFinal_ex(evp_md_ctx, sha256_data, &sha256_data_len);
        if (result != 1) {
            TEST_LOG("EVP_DigestFinal_ex fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
            break;
        }

        if (sha256_data_len != SHA256_DIGEST_LENGTH) {
            TEST_LOG("error sha256_data_len %u", sha256_data_len);
            break;
        }

        TEST_LOG("sha256:");
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            printf("%02x ", sha256_data[i]);
        }
        printf("\n");

        ret = 0;
    } while (0);

    if (fd != -1) {
        close(fd);
        fd = -1;
    }

    if (evp_md_ctx != NULL) {
        EVP_MD_CTX_free(evp_md_ctx);
        evp_md_ctx = NULL;
    }

    return ret;
}

int main()
{
    int ret = TestSha256_1();
    if (ret != 0) {
        TEST_LOG("TestSha256_1 fail!");
    }

    ret = TestSha256_2();
    if (ret != 0) {
        TEST_LOG("TestSha256_2 fail!");
    }

    return 0;
}