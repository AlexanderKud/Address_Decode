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
    char **lines;
    size_t start;
    size_t end;
    unsigned char **results;
    size_t *result_lengths;
    size_t *success_count;
    size_t *failure_count;
    char **failed_lines;
    size_t *failed_lines_count;
} ThreadData;

void* thread_process(void *arg)
{
    // ... (thread_process 函数保持不变)
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
                  // 内存分配失败也算失败
                    data->failed_lines[*data->failed_lines_count] = strdup(line);
                   if (data->failed_lines[*data->failed_lines_count]) {
                        (*data->failed_lines_count)++;
                    }
                    __sync_add_and_fetch(data->failure_count, 1);

                }
                continue;
            }
             // extract_hash160失败,也算解码失败
             data->failed_lines[*data->failed_lines_count] = strdup(line);
              if(data->failed_lines[*data->failed_lines_count]){
                 (*data->failed_lines_count)++;
               }
                __sync_add_and_fetch(data->failure_count, 1);
        }
        else{ // decode_any失败
          data->failed_lines[*data->failed_lines_count] = strdup(line);
          if(data->failed_lines[*data->failed_lines_count]){
            (*data->failed_lines_count)++;
           }
          __sync_add_and_fetch(data->failure_count, 1);
        }
    }
    return NULL;

}

int main(int argc, char *argv[]) {
   // ... (参数解析和之前的代码相同) ...
   const char *inFile = NULL;
    const char *outFileSuccess = NULL;  // 仍然保留，但仅在 -f 模式下使用
    const char *outFileFailure = NULL;  // 仍然保留，但仅在 -f 模式下使用
    const char *singleAddress = NULL;
    int thread_count = 1;
    int use_file_input = 0;

    // 参数解析
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            inFile = argv[++i];
            use_file_input = 1;
        } else if (strcmp(argv[i], "-os") == 0 && i + 1 < argc) {
            outFileSuccess = argv[++i];
        } else if (strcmp(argv[i], "-of") == 0 && i + 1 < argc) {
            outFileFailure = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            thread_count = atoi(argv[++i]);
            if (thread_count <= 0) {
                fprintf(stderr, "线程数量必须为正整数。\n");
                return 1;
            }
        } else if (!use_file_input && !singleAddress) {
            singleAddress = argv[i];
        }
    }

    if (use_file_input && singleAddress) {
        fprintf(stderr, "不能同时指定文件输入和单个地址。\n");
        return 1;
    }

    if (!use_file_input && !singleAddress) {
        fprintf(stderr, "必须提供输入文件 (-f) 或单个地址。\n");
        return 1;
    }

    char **lines = NULL;
    size_t count = 0;

    if (use_file_input) {
      //文件输入模式
        FILE *fin = fopen(inFile, "r");
        if (!fin) {
            perror("无法打开输入文件");
            return 1;
        }
        size_t capacity = 1024;
        lines = malloc(capacity * sizeof(char*));
        if(!lines){
           fclose(fin);
            perror("内存分配失败");
            return 1;
         }

        char buffer[1024];
        while(fgets(buffer,sizeof(buffer),fin)){
           trim_whitespace(buffer);
           if(buffer[0] == 0) continue;
           if(count >= capacity){
             capacity *=2;
             char** temp = realloc(lines, capacity * sizeof(char*));
              if(!temp){
                 for(size_t i = 0; i < count; i++) free(lines[i]);
                 free(lines);
                 fclose(fin);
                 perror("内存分配失败");
                 return 1;
              }
              lines = temp;
            }
            lines[count] = strdup(buffer);
             if(!lines[count]){
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


    } else {
        // 单个地址模式
        lines = malloc(sizeof(char *));
        if (!lines) {
            perror("内存分配失败");
            return 1;
        }
        lines[0] = strdup(singleAddress);
        if (!lines[0]) {
            free(lines);
            perror("内存分配失败");
            return 1;
        }
        count = 1;
    }

    unsigned char **results = malloc(count * sizeof(unsigned char *));
    size_t *result_lengths = malloc(count * sizeof(size_t));
    char **failed_lines = malloc(count * sizeof(char *));  // 用于存储失败的行
    size_t failed_lines_count = 0;

    if (!results || !result_lengths || !failed_lines) {
        fprintf(stderr, "内存分配失败。\n");
        for (size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        free(results);
        free(result_lengths);
        free(failed_lines);
        return 1;
    }
    memset(results, 0, count * sizeof(unsigned char *));
    memset(result_lengths, 0, count * sizeof(size_t));

    size_t success_count = 0;
    size_t failure_count = 0;

    pthread_t *threads = malloc(thread_count * sizeof(pthread_t));
    ThreadData *thread_data = malloc(thread_count * sizeof(ThreadData));

     if(!threads || !thread_data){
      fprintf(stderr,"内存分配失败。\n");
      for(size_t i = 0; i < count; i++) free(lines[i]);
      free(lines);
      free(results);
      free(result_lengths);
      free(failed_lines);
      free(threads);
      free(thread_data);
      return 1;
    }

    // 分配工作给线程
    size_t lines_per_thread = count / thread_count;
    size_t remaining = count % thread_count;

    for(int i = 0; i < thread_count; i++){
       thread_data[i].lines = lines;
       thread_data[i].start = i * lines_per_thread;
       thread_data[i].end = (i+1) * lines_per_thread;
       if(i == thread_count - 1){
         thread_data[i].end += remaining;
       }
       thread_data[i].results = results;
       thread_data[i].result_lengths = result_lengths;
       thread_data[i].success_count = &success_count;
       thread_data[i].failure_count = &failure_count;
        thread_data[i].failed_lines = failed_lines;
        thread_data[i].failed_lines_count = &failed_lines_count;

      if(pthread_create(&threads[i],NULL,thread_process,&thread_data[i])!=0){
          fprintf(stderr,"无法创建线程%d。\n",i);
          for(int j = 0; j < i; j++) pthread_join(threads[j],NULL);
          for(size_t k = 0; k < count; k++) free(lines[k]);
          free(lines);
          free(results);
          free(result_lengths);
          free(failed_lines);
          free(threads);
          free(thread_data);
          return 1;
       }
    }

    //等待所有线程完成
    for(int i = 0; i < thread_count;i++){
      pthread_join(threads[i],NULL);
    }

    // 输出结果
    if (use_file_input) {
        // 文件模式：输出到文件或 stdout，并打印统计信息
         FILE *fout_success = (outFileSuccess && strcmp(outFileSuccess, "-") != 0) ? fopen(outFileSuccess, "w") : stdout;
        FILE *fout_failure = (outFileFailure && strcmp(outFileFailure, "-") != 0) ? fopen(outFileFailure, "w") : stdout;

        if (!fout_success) {
            perror("无法打开成功输出文件");
            if (fout_failure != stdout) fclose(fout_failure);
            goto cleanup;
        }
        if (!fout_failure) {
            perror("无法打开失败输出文件");
            if (fout_success != stdout) fclose(fout_success);
            goto cleanup;
        }

        for (size_t i = 0; i < count; i++) {
            if (results[i] && result_lengths[i] > 0) {
                print_hex(fout_success, results[i], result_lengths[i]);
                fprintf(fout_success, "\n");
                //free(results[i]); //移除
            }
        }
        for (size_t i = 0; i < failed_lines_count; i++) {
            fprintf(fout_failure, "%s\n", failed_lines[i]);
            // free(failed_lines[i]); //移除
        }


        if (fout_success != stdout) fclose(fout_success);
        if (fout_failure != stdout) fclose(fout_failure);

        // 打印统计信息 (仅在文件模式下)
        printf("总处理数量: %zu\n", count);
        printf("成功解码数量: %zu\n", success_count);
        printf("解码失败数量: %zu\n", failure_count);

    } else {
        // 单个地址模式：直接输出到 stdout，不打印统计信息
        if (results[0] && result_lengths[0] > 0) {
            print_hex(stdout, results[0], result_lengths[0]);
            printf("\n");
        } else {
           printf("%s\n", lines[0]); // 打印原始地址
        }
    }
    //修改thread_process
    //统一释放,且优化
    // for (size_t i = 0; i < success_count; i++) { // 只循环成功次数
    //      if (results[i]) free(results[i]);
    // }
    // for (size_t i = 0; i < failed_lines_count; i++) {  // 只循环失败次数
    //      if (failed_lines[i]) free(failed_lines[i]);
    //  }
    free(results);
    free(result_lengths);
    free(failed_lines);

cleanup:
    // 清理
    for (size_t i = 0; i < count; i++) free(lines[i]);
    free(lines);
    // for (size_t i = 0; i < count; i++)  if (results[i]) free(results[i]); // 移除！
    // free(results);
    // free(result_lengths);
    // for(size_t i = 0; i < failed_lines_count; i++) free(failed_lines[i]); //移除
    // free(failed_lines);
    free(threads);
    free(thread_data);

    return 0;
}
