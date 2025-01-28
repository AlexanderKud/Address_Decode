/* Copyright (c) 2025, wanghooj
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "base58_nocheck.h"
#include <string.h>
#include <stdio.h>

/* Base58 字母表 */
static const char *BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* 返回字符 c 在 Base58 字母表中的索引，若找不到则 -1 */
static int base58_char_index(char c) {
    const char *p = strchr(BASE58_ALPHABET, c);
    return p ? (int)(p - BASE58_ALPHABET) : -1;
}

int base58_decode_nocheck(const char *b58_str, unsigned char *out_data, size_t *out_len)
{
    // 数一数开头 '1' 的数量 => 对应 0x00 前导字节
    size_t leading_ones = 0;
    const char *ptr = b58_str;
    while (*ptr == '1') {
        leading_ones++;
        ptr++;
    }

    // 用一个大数缓冲（足够解析常规比特币地址）
    unsigned char temp[64];
    memset(temp, 0, sizeof(temp));

    // 逐字符解析 bigNum = bigNum * 58 + digit
    for (; *ptr; ptr++) {
        int digit = base58_char_index(*ptr);
        if (digit < 0) {
            // 非法字符
            return 0;
        }

        unsigned int carry = (unsigned int)digit;
        for (int i = 63; i >= 0; i--) {
            carry += (unsigned int)temp[i] * 58;
            temp[i] = (unsigned char)(carry & 0xFF);
            carry >>= 8;
        }
        if (carry != 0) {
            // 超出 temp 范围
            return 0;
        }
    }

    // 去掉最高位多余的 0
    int start = 0;
    while (start < 64 && temp[start] == 0) {
        start++;
    }
    size_t value_len = 64 - start;

    // 总长度 = leading_ones + value_len
    size_t total_len = leading_ones + value_len;
    if (total_len > *out_len) {
        // 缓冲区不够
        return 0;
    }

    // 输出
    memset(out_data, 0, leading_ones);
    memcpy(out_data + leading_ones, temp + start, value_len);

    *out_len = total_len;
    return 1;
}
