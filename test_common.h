#ifndef TEST_COMMON_H_
#define TEST_COMMON_H_

#include <stdio.h>
#include <string.h>

#define TEST_FILE_NAME(x) (strrchr(x, '/') ? strrchr(x, '/') + 1 : x)

#define TEST_LOG_FORMAT "[%s][%s][%d]"

#define TEST_LOG(format, ...) printf(TEST_LOG_FORMAT format "\n", TEST_FILE_NAME(__FILE__), __func__, __LINE__, ##__VA_ARGS__)

#endif