/*github.com/8891689 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>

/* 函数声明 */
int segwit_addr_decode(int*, uint8_t*, size_t*, const char*, const char*);
int base58_decode_nocheck(const char *input, unsigned char *out, size_t *outlen);

/* -------------------------------------------------------------------------
 * 1. 打印hex
 * -------------------------------------------------------------------------*/
static void print_hex(FILE *fp, const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++){
        fprintf(fp, "%02x", data[i]);
    }
}

/* -------------------------------------------------------------------------
 * 2. 去除行首尾空白
 * -------------------------------------------------------------------------*/
static void trim_whitespace(char *s)
{
    // 去尾部
    size_t l = strlen(s);
    while(l > 0 && isspace((unsigned char)s[l-1])){
        s[--l] = 0;
    }
    // 去头部
    int start = 0;
    while(s[start] && isspace((unsigned char)s[start])){
        start++;
    }
    if(start > 0){
        memmove(s, s + start, l + 1 - start);
    }
}

/* -------------------------------------------------------------------------
 * 3. decode_as_hex
 *    若输入以"0x"开头 => 去掉"0x", 把后面当 hex => 全部解码输出
 * -------------------------------------------------------------------------*/
static int decode_as_hex(const char *addr, unsigned char *out, size_t *outlen)
{
    if(strncmp(addr,"0x",2)!=0 && strncmp(addr,"0X",2)!=0){
        return 0; // not hex
    }
    // 去掉 0x
    const char *hexPart = addr + 2;

    size_t hlen = strlen(hexPart);
    if(hlen == 0){
        return 0;
    }
    // 若长度是奇数，也可以继续解(前面补0)
    // 这里简单处理 => 如果奇数 => prepend '0'
    char *tmp = NULL;
    if((hlen % 2) != 0){
        tmp = (char*)malloc(hlen + 2);
        if(!tmp) return 0;
        tmp[0] = '0';
        strcpy(tmp + 1, hexPart);
        hexPart = tmp;
        hlen++;
    }

    size_t outPos = 0;
    for (size_t i = 0; i < hlen; i += 2){
        char buf[3];
        buf[0] = hexPart[i];
        buf[1] = hexPart[i+1];
        buf[2] = 0;
        unsigned int val = 0;
        if(sscanf(buf, "%x", &val) != 1){
            if(tmp) free(tmp);
            return 0;
        }
        out[outPos++] = (unsigned char)val;
    }
    if(tmp) free(tmp);

    *outlen = outPos;
    return 1;
}

/* -------------------------------------------------------------------------
 * 4. decode_as_segwit_anyhrp
 *    给定 hrp, 调 segwit_addr_decode. 这里不做 program长度限制
 * -------------------------------------------------------------------------*/
static int decode_as_segwit_anyhrp(const char *addr, const char *hrp,
                                   unsigned char *out, size_t *outlen)
{
    int witver;
    uint8_t witprog[80]; // 给它大点空间
    size_t wlen = 0;
    if(!segwit_addr_decode(&witver, witprog, &wlen, hrp, addr)){
        return 0;
    }
    // 不做长度限制，直接复制
    memcpy(out, witprog, wlen);
    *outlen = wlen;
    return 1;
}

/* -------------------------------------------------------------------------
 * 5. decode_as_segwit
 *    判断前缀 bc1/tb1/ltc1/tltc1/btg1/... => 试 decode
 *    也可改成通配: 查找 'xxx1' 之前做hrp, 但这里演示固定几种
 * -------------------------------------------------------------------------*/
static int decode_as_segwit(const char *addr,
                            unsigned char *out, size_t *outlen)
{
    // 你可以继续添加 hrp
    if(strncmp(addr,"bc1",3)==0){
        return decode_as_segwit_anyhrp(addr, "bc", out, outlen);
    }
    if(strncmp(addr,"tb1",3)==0){
        return decode_as_segwit_anyhrp(addr, "tb", out, outlen);
    }
    if(strncmp(addr,"ltc1",4)==0){
        return decode_as_segwit_anyhrp(addr, "ltc", out, outlen);
    }
    if(strncmp(addr,"tltc1",5)==0){
        return decode_as_segwit_anyhrp(addr, "tltc", out, outlen);
    }
    if(strncmp(addr,"btg1",4)==0){
        return decode_as_segwit_anyhrp(addr, "btg", out, outlen);
    }
    // ...
    return 0;
}

/* -------------------------------------------------------------------------
 * 6. decode_as_bch_minimal
 *    若含"bitcoincash:"或"bchtest:" 或首字母=='q'/'p' => base32 => 全部转8bit
 *    不做PolyMod校验
 * -------------------------------------------------------------------------*/
static const char *BCH_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
static int8_t BCH_REV[128];
static int inited_bch = 0;

static void init_bch_rev(void)
{
    if(inited_bch) return;
    memset(BCH_REV, -1, sizeof(BCH_REV));
    for(int i = 0; i < 32; i++){
        unsigned char c = (unsigned char)BCH_CHARS[i];
        BCH_REV[c] = i;
        // 若要兼容大写 => BCH_REV[toupper(c)] = i;
    }
    inited_bch = 1;
}

static int decode_as_bch_minimal(const char *addr, unsigned char *out, size_t *outlen)
{
    init_bch_rev();

    // 1) 先找':', 取后面
    const char *dataPart = addr;
    const char *col = strchr(addr, ':');
    if(col) dataPart = col + 1;

    // 2) 转小写+查表
    char lower[512];
    size_t alen = strlen(dataPart);
    if(alen >= sizeof(lower)){
        return 0;
    }
    for(size_t i = 0; i < alen; i++){
        lower[i] = (char)tolower((unsigned char)dataPart[i]);
    }
    lower[alen] = 0;

    int8_t vals[512];
    int idx = 0;
    for(size_t i = 0; i < alen; i++){
        unsigned char c = (unsigned char)lower[i];
        if(c >= 128 || BCH_REV[c] < 0){
            return 0;
        }
        vals[idx++] = BCH_REV[c];
    }

    // 3) 5bit -> 8bit (不做任何长度限制)
    uint32_t val = 0;
    int bits = 0;
    size_t outPos = 0;
    for(int i = 0; i < idx; i++){
        val = (val << 5) | (vals[i] & 31);
        bits += 5;
        while(bits >= 8){
            bits -= 8;
            out[outPos++] = (unsigned char)((val >> bits) & 0xFF);
            if(outPos >= 80) break; // 避免溢出
        }
    }
    *outlen = outPos;
    return 1;
}

/* -------------------------------------------------------------------------
 * 7. decode_as_base58_nolimit
 *    只要没有非法字符，就解出全部字节(可能是0~N) => 输出
 * -------------------------------------------------------------------------*/
static int decode_as_base58_nolimit(const char *addr, unsigned char *out, size_t *outlen)
{
    unsigned char tmp[512];
    size_t tlen = sizeof(tmp);
    if(!base58_decode_nocheck(addr, tmp, &tlen)){
        return 0;
    }
    if(tlen == 0){
        return 0;
    }
    memcpy(out, tmp, tlen);
    *outlen = tlen;
    return 1;
}

/* -------------------------------------------------------------------------
 * 8. 定义地址类型枚举
 * -------------------------------------------------------------------------*/
typedef enum {
    ADDR_TYPE_UNKNOWN,
    ADDR_TYPE_BASE58,
    ADDR_TYPE_SEGWIT,
    ADDR_TYPE_BCH,
    ADDR_TYPE_HEX
} AddressType;

/* -------------------------------------------------------------------------
 * 9. decode_any
 * -------------------------------------------------------------------------*/
static int decode_any(const char *inp, unsigned char *out, size_t *outlen, AddressType *type)
{
    // 初始化类型为未知
    if(type) *type = ADDR_TYPE_UNKNOWN;

    // 0) if starts with '0x' => hex
    if(strncmp(inp,"0x",2)==0 || strncmp(inp,"0X",2)==0){
        if(decode_as_hex(inp, out, outlen)){
            if(type) *type = ADDR_TYPE_HEX;
            return 1;
        }
    }

    // 1) segwit
    if(decode_as_segwit(inp, out, outlen)){
        if(type) *type = ADDR_TYPE_SEGWIT;
        return 1;
    }

    // 2) bch?
    if(strstr(inp,"bitcoincash:") || strstr(inp,"bchtest:") ||
       inp[0] == 'q' || inp[0] == 'p') {
        if(decode_as_bch_minimal(inp, out, outlen)){
            if(type) *type = ADDR_TYPE_BCH;
            return 1;
        }
    }

    // 3) fallback => base58
    if(decode_as_base58_nolimit(inp, out, outlen)){
        if(type) *type = ADDR_TYPE_BASE58;
        return 1;
    }

    // all fail
    return 0;
}

/* -------------------------------------------------------------------------
 * 10. 提取hash160
 * -------------------------------------------------------------------------*/
static int extract_hash160(AddressType type, const unsigned char *decoded, size_t decoded_len, unsigned char *hash160, size_t *hash_len)
{
    switch(type){
        case ADDR_TYPE_BASE58:
            if(decoded_len < 25){
                return 0;
            }
            // Base58: version (1 byte) + hash160 (20 bytes) + checksum (4 bytes)
            memcpy(hash160, decoded + 1, 20);
            *hash_len = 20;
            return 1;
        case ADDR_TYPE_SEGWIT:
            // SegWit: witness version (1 byte) + program (typically 20 or 32 bytes)
            if(decoded_len < 1){
                return 0;
            }
            memcpy(hash160, decoded, decoded_len);
            *hash_len = decoded_len;
            return 1;
        case ADDR_TYPE_BCH:
            // BCH Minimal: 跳过前两个字符（1字节），复制20字节hash160
            if(decoded_len < 25){
                return 0;
            }
            // 跳过第一个字节（版本），复制接下来的20字节
            memcpy(hash160, decoded + 1, 20);
            *hash_len = 20;
            return 1;
        case ADDR_TYPE_HEX:
            // 如果是hex编码，假设直接是hash160
            if(decoded_len != 20){
                return 0;
            }
            memcpy(hash160, decoded, 20);
            *hash_len = 20;
            return 1;
        default:
            return 0;
    }
}

/* -------------------------------------------------------------------------
 * 11. 线程相关结构和变量
 * -------------------------------------------------------------------------*/
typedef struct {
    char **lines;        // 输入地址行
    size_t start;        // 起始索引（包含）
    size_t end;          // 结束索引（不包含）
    unsigned char **results; // 输出结果，每个线程独立分配
    size_t *result_lengths;  // 输出结果长度
    size_t *success_count;   // 成功计数
    size_t *failure_count;   // 失败计数
} ThreadData;

/* -------------------------------------------------------------------------
 * 12. 线程处理函数
 * -------------------------------------------------------------------------*/
void* thread_process(void *arg)
{
    ThreadData *data = (ThreadData*)arg;
    for(size_t i = data->start; i < data->end; i++){
        const char *line = data->lines[i];
        unsigned char decoded[80];
        size_t decoded_len = 0;
        AddressType type = ADDR_TYPE_UNKNOWN;

        if(decode_any(line, decoded, &decoded_len, &type)){
            unsigned char hash160[20];
            size_t hash_len = 0;
            if(extract_hash160(type, decoded, decoded_len, hash160, &hash_len)){
                // 分配内存存储结果
                data->results[i] = (unsigned char*)malloc(hash_len);
                if(data->results[i]){
                    memcpy(data->results[i], hash160, hash_len);
                    data->result_lengths[i] = hash_len;
                    __sync_add_and_fetch(data->success_count, 1);
                } else {
                    __sync_add_and_fetch(data->failure_count, 1);
                }
                continue;
            }
        }
        // 解码或提取失败
        data->results[i] = NULL;
        data->result_lengths[i] = 0;
        __sync_add_and_fetch(data->failure_count, 1);
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * 13. 主函数
 * -------------------------------------------------------------------------*/
int main(int argc, char *argv[])
{
    const char *inFile = NULL;
    const char *outFile = NULL;
    int thread_count = 1; // 默认单线程

    // 解析命令行参数
    for(int i = 1; i < argc; i++){
        if(strcmp(argv[i], "-f") == 0 && i + 1 < argc){
            inFile = argv[++i];
        }
        else if(strcmp(argv[i], "-o") == 0 && i + 1 < argc){
            outFile = argv[++i];
        }
        else if(strcmp(argv[i], "-t") == 0 && i + 1 < argc){
            thread_count = atoi(argv[++i]);
            if(thread_count <= 0){
                fprintf(stderr, "线程数量必须为正整数。\n");
                return 1;
            }
        }
    }

    if(!inFile || !outFile){
        fprintf(stderr, "用法: %s -f <输入文件> -o <输出文件> [-t <线程数量>]\n", argv[0]);
        return 1;
    }

    // 读取所有行到内存
    FILE *fin = fopen(inFile, "r");
    if(!fin){
        perror("无法打开输入文件");
        return 1;
    }

    // 动态数组存储行
    size_t capacity = 1024;
    size_t count = 0;
    char **lines = malloc(capacity * sizeof(char*));
    if(!lines){
        fclose(fin);
        perror("内存分配失败");
        return 1;
    }

    char buffer[1024];
    while(fgets(buffer, sizeof(buffer), fin)){
        trim_whitespace(buffer);
        if(buffer[0] == 0){
            continue; // 空行
        }
        if(count >= capacity){
            capacity *= 2;
            char **temp = realloc(lines, capacity * sizeof(char*));
            if(!temp){
                // 清理已分配的内存
                for(size_t i = 0; i < count; i++) free(lines[i]);
                free(lines);
                fclose(fin);
                perror("内存重新分配失败");
                return 1;
            }
            lines = temp;
        }
        lines[count] = strdup(buffer);
        if(!lines[count]){
            // 清理已分配的内存
            for(size_t i = 0; i < count; i++) free(lines[i]);
            free(lines);
            fclose(fin);
            perror("内存分配失败");
            return 1;
        }
        count++;
    }
    fclose(fin);

    if(count == 0){
        fprintf(stderr, "输入文件为空或无有效行。\n");
        free(lines);
        return 1;
    }

    // 分配结果数组
    unsigned char **results = malloc(count * sizeof(unsigned char*));
    size_t *result_lengths = malloc(count * sizeof(size_t));
    if(!results || !result_lengths){
        fprintf(stderr, "内存分配失败。\n");
        for(size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        free(results);
        free(result_lengths);
        return 1;
    }
    memset(results, 0, count * sizeof(unsigned char*));
    memset(result_lengths, 0, count * sizeof(size_t));

    // 计数
    size_t success_count = 0;
    size_t failure_count = 0;

    // 创建线程
    pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
    ThreadData *thread_data = malloc(thread_count * sizeof(ThreadData));
    if(!threads || !thread_data){
        fprintf(stderr, "内存分配失败。\n");
        for(size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        free(results);
        free(result_lengths);
        free(threads);
        free(thread_data);
        return 1;
    }

    // 分配工作给每个线程
    size_t lines_per_thread = count / thread_count;
    size_t remaining = count % thread_count;

    for(int i = 0; i < thread_count; i++){
        thread_data[i].lines = lines;
        thread_data[i].start = i * lines_per_thread;
        thread_data[i].end = (i + 1) * lines_per_thread;
        if(i == thread_count - 1){
            thread_data[i].end += remaining; // 最后一个线程处理剩余的行
        }
        thread_data[i].results = results;
        thread_data[i].result_lengths = result_lengths;
        thread_data[i].success_count = &success_count;
        thread_data[i].failure_count = &failure_count;

        if(pthread_create(&threads[i], NULL, thread_process, &thread_data[i]) != 0){
            fprintf(stderr, "无法创建线程 %d。\n", i);
            // 处理已创建的线程
            for(int j = 0; j < i; j++) pthread_join(threads[j], NULL);
            for(size_t k = 0; k < count; k++) free(lines[k]);
            free(lines);
            free(results);
            free(result_lengths);
            free(threads);
            free(thread_data);
            return 1;
        }
    }

    // 等待所有线程完成
    for(int i = 0; i < thread_count; i++){
        pthread_join(threads[i], NULL);
    }

    // 打开输出文件
    FILE *fout = fopen(outFile, "w");
    if(!fout){
        perror("无法打开输出文件");
        // 处理内存
        for(size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        for(size_t i = 0; i < count; i++) if(results[i]) free(results[i]);
        free(results);
        free(result_lengths);
        free(threads);
        free(thread_data);
        return 1;
    }

    // 写入结果
    for(size_t i = 0; i < count; i++){
        if(results[i] && result_lengths[i] > 0){
            print_hex(fout, results[i], result_lengths[i]);
            fprintf(fout, "\n");
            free(results[i]);
        }
        // 如果需要保留失败的行，可以在这里处理
    }

    fclose(fout);

    // 输出处理统计
    printf("总处理数量: %zu\n", count);
    printf("成功解码数量: %zu\n", success_count);
    printf("解码失败数量: %zu\n", failure_count);

    // 清理内存
    for(size_t i = 0; i < count; i++) free(lines[i]);
    free(lines);
    free(results);
    free(result_lengths);
    free(threads);
    free(thread_data);

    return 0;
}
