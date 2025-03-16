/* Copyright (c) 2025, 8891689
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
#ifndef BASE58_NOCHECK_H
#define BASE58_NOCHECK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 将 Base58 字符串解码为字节数组（不做校验和比较）。
 *
 * 解码后典型结果可包含:
 *   [ 1字节 version ] [ 20字节 payload ] [ (可选)4字节校验和等 ] 
 * 但本函数不再做校验和检查，亦不会剔除末尾 4 字节。
 *
 * @param b58_str   输入的 Base58 字符串
 * @param out_data  输出缓冲区
 * @param out_len   输入时表示缓冲区大小，输出时表示实际解码得到的字节数
 * @return 1=解码成功, 0=失败(包含非法字符或输出缓冲不够)
 */
int base58_decode_nocheck(const char *b58_str, unsigned char *out_data, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif // BASE58_NOCHECK_H
