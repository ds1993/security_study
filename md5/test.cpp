#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/md5.h>
#include <openssl/err.h>

#include "test_common.h"

int main()
{
    int fd = -1;
    MD5_CTX md5_ctx;
    uint8_t md5_data[MD5_DIGEST_LENGTH] = { 0 };

    do {
        fd = open("../test.bin", O_RDONLY);
        if (fd == -1) {
            TEST_LOG("open fail, errno: %d, %s", errno, strerror(errno));
            break;
        }

        int result = MD5_Init(&md5_ctx);
        if (result != 1) {
            TEST_LOG("MD5_Init fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
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
            result = MD5_Update(&md5_ctx, buffer, read_len);
            if (result != 1) {
                TEST_LOG("MD5_Update fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
                read_len = -1;
                break;
            }
        } while (1);

        if (read_len != 0) {
            TEST_LOG("read fail!");
            break;
        }

        result = MD5_Final(md5_data, &md5_ctx);
        if (result != 1) {
            TEST_LOG("MD5_Final fail, error: %ld, %s", ERR_get_error(), ERR_reason_error_string(ERR_get_error()));
            break;
        }

        TEST_LOG("md5:");
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x ", md5_data[i]);
        }
        printf("\n");
    } while (0);

    if (fd != -1) {
        close(fd);
        fd = -1;
    }

    return 0;
}