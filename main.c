/*github.com/8891689 */
// gcc -O3 -lpthread -Wall -Wextra -march=native -static base58.c bech32.c cashaddr.c main.c sha256.c -o decode
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <pthread.h> // 對於 Linux/macOS，直接使用。對於 Windows，需要 MinGW 或 pthreads-w32。
#include <errno.h>
#include <stdbool.h> // For bool type

#ifdef _WIN32
#include <windows.h> // For GetSystemInfo to get processor count
#else
#include <unistd.h>  // For sysconf to get processor count
#endif

// 引入自定義庫的頭文件
#include "sha256.h"
#include "base58.h"
#include "bech32.h"
#include "cashaddr.h" // 確保此處路徑正確，如果您的文件是 cashaddr.h

/* -------------------------------------------------------------------------
 * 1. 輔助函數：將字節數組轉換為十六進制字符串
 * -------------------------------------------------------------------------*/
static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_str[i * 2], "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';
}

/* -------------------------------------------------------------------------
 * 2. 輔助函數：將十六進制字符串轉換為字節數組 (用於Hex地址的內部解析)
 * -------------------------------------------------------------------------*/
static int hex_to_bytes(const char *hex_str, unsigned char *bytes_out, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) { // 十六進制字符串長度必須是偶數
        return 0;
    }
    size_t bytes_len = len / 2;
    if (bytes_len > max_len) { // 超出緩衝區
        return 0;
    }
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int val;
        if (sscanf(hex_str + (i * 2), "%2x", &val) != 1) {
            return 0; // 無效十六進制字符
        }
        bytes_out[i] = (unsigned char)val;
    }
    return (int)bytes_len;
}

/* -------------------------------------------------------------------------
 * 3. 去除行首尾空白
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
 * 4. decode_address_general
 *    嘗試解碼地址，並提取其核心哈希/程序字節及其長度。
 *    此函數不再判斷是否為 20 字節，只要能成功解析並提取出某個哈希/程序，
 *    就將其存入 out_bytes 和 out_len，並返回 1；否則返回 0。
 * -------------------------------------------------------------------------*/
static int decode_address_general(const char *addr_str, unsigned char *out_bytes, size_t *out_len) {
    unsigned char temp_decoded_buf[64]; // 足夠容納大多數解碼中間結果
    size_t current_len = 0; // **修正：初始化為 0**
    int witver;

    // 1. 嘗試 Base58Check 解碼 (P2PKH, P2SH)
    // base58_decode_check 會返回 payload (去除4字節校驗和)，並驗證校驗和
    // 將結果長度存入 current_len 的地址
    uint8_t *b58_payload = base58_decode_check(addr_str, &current_len); // **修正：確保這裡是 ¤t_len**
    if (b58_payload) {
        // 對於標準的 P2PKH/P2SH 地址，payload 應為 21 字節 (1字節版本 + 20字節 Hash160)
        // 這裡我們提取出核心的 Hash160 (20字節)。
        // 即使 Base58 地址的 payload 更長（如某些擴展類型），我們也假設核心是20字節。
        if (current_len >= 20) { // 確保至少有 20 字節的數據可以複製
            // 對於 Base58Check，核心哈希通常是 payload 的第二個字節開始的 20 字節
            // 所以從 b58_payload + 1 複製 20 字節
            memcpy(out_bytes, b58_payload + 1, 20); 
            *out_len = 20; // 統一輸出為 20 字節
            free(b58_payload);
            return 1;
        }
        free(b58_payload);
    }

    // 2. 嘗試 SegWit 解碼 (P2WPKH, P2WSH, P2TR)
    const char *hrps[] = {"bc", "tb", "ltc", "tltc", "btg", NULL};
    for (int i = 0; hrps[i] != NULL; ++i) {
        // segwit_prog_len_val 用作 segwit_addr_decode 的輸入 (緩衝區大小) 和輸出 (實際長度)
        size_t segwit_prog_len_val = sizeof(temp_decoded_buf); 
        if (segwit_addr_decode(addr_str, hrps[i], &witver, temp_decoded_buf, &segwit_prog_len_val)) {
            // SegWit 地址的核心是 Witness Program (witprog)
            // 將 witprog 直接存入 out_bytes
            memcpy(out_bytes, temp_decoded_buf, segwit_prog_len_val);
            *out_len = segwit_prog_len_val; // 輸出其真實長度（20、32等）
            return 1; // 成功解碼 SegWit 地址並提取其程序
        }
    }

    // 3. 嘗試 CashAddr 解碼 (P2PKH, P2SH)
    CashAddrResult cash_result;
    if (decode_cashaddr(addr_str, &cash_result) == 0) {
        // CashAddr 庫直接提供了 Hash160 的十六進制字符串
        // 將其轉換回字節並存入 out_bytes
        current_len = hex_to_bytes(cash_result.hash160, out_bytes, 20); // Hash160 應為 20 字節
        if (current_len == 20) {
            *out_len = 20;
            return 1;
        }
    }

    // 4. 嘗試直接 Hex 解碼
    // current_len 從 hex_to_bytes 的返回值獲取
    if (strncmp(addr_str, "0x", 2) == 0 || strncmp(addr_str, "0X", 2) == 0) {
        current_len = hex_to_bytes(addr_str + 2, out_bytes, sizeof(temp_decoded_buf));
    } else {
        current_len = hex_to_bytes(addr_str, out_bytes, sizeof(temp_decoded_buf));
    }

    if (current_len > 0) { // 如果能解碼出任何長度的十六進制字節
        // 對於裸 Hex，我們將其視為其本身就是核心數據。
        // 其長度由 hex_to_bytes 決定。
        *out_len = current_len;
        return 1;
    }

    return 0; // 所有嘗試都失敗
}

/* -------------------------------------------------------------------------
 * 5. 线程相關結構和變量
 * -------------------------------------------------------------------------*/

// 結果狀態碼
#define DECODE_FAILED            -1 // 完全解碼失敗
#define SUCCESS_NON_STANDARD_HASH 0 // 解碼成功，但哈希長度非 20 字節
#define SUCCESS_STANDARD_HASH     1 // 解碼成功，哈希長度為 20 字節 (Hash160)

// ProcessedResult 結構用於存儲每行的處理結果
typedef struct {
    char *original_line;     // 原始輸入行，用於失敗時輸出 (包括金額部分)
    char address_part[512];  // 提取的地址部分 (不含金額)，用於解碼
    char output_hex_str[65]; // 提取的核心哈希/程序字節的十六進制表示 (最長 32*2+1)
    int status;              // -1: 解碼失敗, 0: 非標準哈希, 1: 標準哈希
} ProcessedResult;

// ThreadData 結構用於傳遞給每個線程的數據
typedef struct {
    char **lines; // 指向所有原始輸入行的數組
    size_t start; // 當前線程處理的起始行索引
    size_t end;   // 當前線程處理的結束行索引 (不包含)
    ProcessedResult *results; // 指向主線程創建的總結果數組
} ThreadData;

// 線程處理函數
void* thread_process(void *arg)
{
    ThreadData *data = (ThreadData*)arg;
    for(size_t i = data->start; i < data->end; i++){
        char *full_line = data->lines[i];

        data->results[i].original_line = strdup(full_line);
        if (!data->results[i].original_line) {
            data->results[i].status = DECODE_FAILED;
            continue;
        }

        // 自動去掉前面的金額，只保留地址部分
        char *tab_pos = strchr(full_line, '\t');
        if (tab_pos) {
            size_t addr_len = tab_pos - full_line;
            if (addr_len >= sizeof(data->results[i].address_part)) {
                data->results[i].status = DECODE_FAILED; // 地址部分過長
                continue;
            }
            strncpy(data->results[i].address_part, full_line, addr_len);
            data->results[i].address_part[addr_len] = '\0';
        } else {
            strncpy(data->results[i].address_part, full_line, sizeof(data->results[i].address_part) - 1);
            data->results[i].address_part[sizeof(data->results[i].address_part) - 1] = '\0';
        }
        trim_whitespace(data->results[i].address_part);

        if (data->results[i].address_part[0] == '\0') {
            data->results[i].status = DECODE_FAILED;
            continue;
        }

        unsigned char extracted_bytes[64]; // 臨時緩衝區用於接收解碼出的字節
        size_t extracted_len = 0;

        // 嘗試通用解碼
        if (decode_address_general(data->results[i].address_part, extracted_bytes, &extracted_len)) {
            // 解碼成功，現在判斷哈希長度是否標準 (20 字節)
            if (extracted_len == 20) {
                data->results[i].status = SUCCESS_STANDARD_HASH;
                bytes_to_hex(extracted_bytes, 20, data->results[i].output_hex_str);
            } else {
                // 解碼成功但哈希長度非 20 字節，標記為非標準
                data->results[i].status = SUCCESS_NON_STANDARD_HASH;
                bytes_to_hex(extracted_bytes, extracted_len, data->results[i].output_hex_str);
            }
        } else {
            // 完全解碼失敗
            data->results[i].status = DECODE_FAILED;
        }
    }
    return NULL;
}

// 比較函數，用於 qsort 排序十六進制字符串
int compare_hex_strings(const void *a, const void *b) {
    const ProcessedResult *res_a = (const ProcessedResult *)a;
    const ProcessedResult *res_b = (const ProcessedResult *)b;
    return strcmp(res_a->output_hex_str, res_b->output_hex_str);
}

int main(int argc, char *argv[]) {
    char *input_source = NULL; // 文件名或單個地址
    char *output_base_name = "output"; // 默認輸出文件基礎名
    bool use_default_output_name = true; // 判斷是否使用了 -o 選項

    // 獲取 CPU 核心數作為默認線程數
    int thread_count = 4; // 默認值
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    thread_count = sysinfo.dwNumberOfProcessors;
#else
    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus > 0) {
        thread_count = (int)num_cpus;
    }
#endif
    if (thread_count == 0) thread_count = 1; // 至少一個線程

    // 命令行參數解析
    if (argc == 2) {
        input_source = argv[1];
        // output_base_name 保持默認 "output"，use_default_output_name 保持 true
    } else if (argc == 4 && strcmp(argv[1], "-o") == 0) {
        output_base_name = argv[2];
        input_source = argv[3];
        use_default_output_name = false; // -o 選項被使用
    } else {
        fprintf(stderr, "Usage  : %s <file or address>\n", argv[0]);
        fprintf(stderr, "  Or   : %s -o <Output document prefix> <file or address>\n", argv[0]);
        fprintf(stderr, "Example: \n");
        fprintf(stderr, "         ./decode Input_file_containing_addresses.txt\n");
        fprintf(stderr, "         ./decode 19qZAgZM4dniNqwuYmQca7FBReTLGX9xyS\n");
        fprintf(stderr, "         ./decode -o <Output_document_prefix> <Input_file_containing_addresses.txt>\n");
        fprintf(stderr, "         ./decode -o <Output_document_prefix> <19qZAgZM4dniNqwuYmQca7FBReTLGX9xyS>\n");
        fprintf(stderr, " Tip   : <file or address> is \"-\" means reading from standard input.\n");
        return 1;
    }

    char outFileSuccessPath[256];
    char outFileFailurePath[256];

    char **lines = NULL;
    size_t count = 0; // 總處理行數
    bool is_file_input = false; // 判斷輸入源是否為文件

    // 判斷輸入源是文件還是單個地址
    FILE *fin = NULL;
    if (strcmp(input_source, "-") == 0) { // 標準輸入
        fin = stdin;
        is_file_input = true;
    } else {
        fin = fopen(input_source, "r");
        if (fin) { // 如果成功打開文件，則為文件輸入
            is_file_input = true;
        } else { // 否則視為單個地址輸入
            is_file_input = false;
            // 如果文件不存在，錯誤碼是 ENOENT，這表示確實是單個地址輸入
            // 如果是其他文件錯誤，則打印錯誤並退出
            if (errno != ENOENT) {
                perror("無法打開輸入文件");
                return 1;
            }
        }
    }
    
    // 判斷是否為單個地址且需要控制台輸出模式 (即沒有使用 -o 選項)
    bool is_single_address_console_output_mode = !is_file_input && use_default_output_name;

    if (is_file_input) {
        // 文件輸入模式
        size_t capacity = 1024;
        lines = (char**)malloc(capacity * sizeof(char*));
        if(!lines){
           if (fin != stdin) fclose(fin);
           perror("內存分配失敗");
           return 1;
        }

        char buffer[1024];
        while(fgets(buffer, sizeof(buffer), fin)){
           if(count >= capacity){
             capacity *=2;
             char** temp = (char**)realloc(lines, capacity * sizeof(char*));
              if(!temp){
                 for(size_t i = 0; i < count; i++) free(lines[i]);
                 free(lines);
                 if (fin != stdin) fclose(fin);
                 perror("內存分配失敗");
                 return 1;
              }
              lines = temp;
            }
            lines[count] = strdup(buffer);
             if(!lines[count]){
                for(size_t i = 0; i < count; i++) free(lines[i]);
                 free(lines);
                 if (fin != stdin) fclose(fin);
                 perror("內存分配失敗");
                 return 1;
             }
            count++;
        }
        if (fin != stdin) fclose(fin);
         if(count == 0){
            fprintf(stderr, "輸入文件/標準輸入為空或無有效行。\n");
            free(lines);
            return 1;
         }
    } else {
        // 單個地址模式
        lines = (char**)malloc(sizeof(char *));
        if (!lines) {
            perror("內存分配失敗");
            return 1;
        }
        lines[0] = strdup(input_source);
        if (!lines[0]) {
            free(lines);
            perror("內存分配失敗");
            return 1;
        }
        count = 1;
    }

    // 初始化 ProcessedResult 結構體數組
    ProcessedResult *all_results = (ProcessedResult*)malloc(count * sizeof(ProcessedResult));
    if (!all_results) {
        fprintf(stderr, "內存分配失敗。\n");
        for (size_t i = 0; i < count; i++) free(lines[i]);
        free(lines);
        return 1;
    }

    pthread_t *threads = (pthread_t*)malloc(thread_count * sizeof(pthread_t));
    ThreadData *thread_data = (ThreadData*)malloc(thread_count * sizeof(ThreadData));

    if(!threads || !thread_data){
      fprintf(stderr,"內存分配失敗。\n");
      for(size_t i = 0; i < count; i++) free(lines[i]);
      free(lines);
      free(all_results);
      free(threads);
      free(thread_data);
      return 1;
    }

    // 將工作分配給各個線程
    size_t lines_per_thread = count / thread_count;
    size_t remaining = count % thread_count;

    for(int i = 0; i < thread_count; i++){
       thread_data[i].lines = lines;
       thread_data[i].start = i * lines_per_thread;
       thread_data[i].end = (i+1) * lines_per_thread;
       if(i == thread_count - 1){
         thread_data[i].end += remaining;
       }
       thread_data[i].results = all_results;

      if(pthread_create(&threads[i],NULL,thread_process,&thread_data[i])!=0){
          fprintf(stderr,"無法創建線程%d。\n",i);
          for(int j = 0; j < i; j++) pthread_join(threads[j],NULL);
          for(size_t k = 0; k < count; k++) {
              free(lines[k]);
              if(all_results[k].original_line) free(all_results[k].original_line);
          }
          free(lines); free(all_results); free(threads); free(thread_data);
          return 1;
       }
    }

    // 等待所有線程完成
    for(int i = 0; i < thread_count;i++){
      pthread_join(threads[i],NULL);
    }

    // 統計和收集結果
    size_t standard_hash_count = 0;
    size_t non_standard_or_failed_count = 0;
    
    // 為標準哈希結果分配一個臨時數組以進行排序和去重
    ProcessedResult *standard_hashes_collection = NULL; // 只有在有標準哈希時才分配

    // 分離成功標準哈希和失敗/非標準哈希
    for (size_t i = 0; i < count; ++i) {
        if (all_results[i].status == SUCCESS_STANDARD_HASH) {
            standard_hash_count++;
        } else {
            non_standard_or_failed_count++;
        }
    }

    if (standard_hash_count > 0) {
        standard_hashes_collection = (ProcessedResult*)malloc(standard_hash_count * sizeof(ProcessedResult));
        if (!standard_hashes_collection) {
            fprintf(stderr, "內存分配失敗 (結果收集)。\n");
            goto cleanup;
        }
        size_t current_collection_idx = 0;
        for(size_t i = 0; i < count; ++i) {
            if (all_results[i].status == SUCCESS_STANDARD_HASH) {
                strcpy(standard_hashes_collection[current_collection_idx].output_hex_str, all_results[i].output_hex_str);
                current_collection_idx++;
            }
        }
    }

    // 對標準哈希結果進行排序
    if (standard_hash_count > 1) {
        qsort(standard_hashes_collection, standard_hash_count, sizeof(ProcessedResult), compare_hex_strings);
    }

    // 輸出處理
    if (is_single_address_console_output_mode) {
        // 單個地址且無 -o 參數，只輸出成功的 Hash160 到控制台
        if (standard_hash_count > 0) {
            // 對於單個地址，standard_hash_count 應為 0 或 1，因此直接輸出第一個即可
            fprintf(stdout, "%s\n", standard_hashes_collection[0].output_hex_str);
        }
        // 失敗或非標準哈希，不輸出 (符合 "不要輸出文檔" 要求)
    } else {
        // 文件輸入模式，或單個地址但有 -o 參數，輸出到文件
        snprintf(outFileSuccessPath, sizeof(outFileSuccessPath), "%s_success.txt", output_base_name);
        snprintf(outFileFailurePath, sizeof(outFileFailurePath), "%s_failure.txt", output_base_name);

        FILE *fout_success = fopen(outFileSuccessPath, "w");
        FILE *fout_failure = fopen(outFileFailurePath, "w");

        if (!fout_success) {
            perror("無法打開成功輸出文件");
            if (fout_failure) fclose(fout_failure);
            goto cleanup;
        }
        if (!fout_failure) {
            perror("無法打開失敗輸出文件");
            if (fout_success) fclose(fout_success);
            goto cleanup;
        }

        // 輸出成功結果 (自動排除重複項)
        if (standard_hash_count > 0) {
            fprintf(fout_success, "%s\n", standard_hashes_collection[0].output_hex_str);
            for (size_t i = 1; i < standard_hash_count; ++i) {
                if (strcmp(standard_hashes_collection[i].output_hex_str, standard_hashes_collection[i-1].output_hex_str) != 0) {
                    fprintf(fout_success, "%s\n", standard_hashes_collection[i].output_hex_str);
                }
            }
        }

        // 輸出失敗或非標準哈希結果到日誌文件
        for (size_t i = 0; i < count; i++) {
            if (all_results[i].status == DECODE_FAILED) {
                fprintf(fout_failure, "[DECODE_FAILED] %s", all_results[i].original_line);
            } else if (all_results[i].status == SUCCESS_NON_STANDARD_HASH) {
                fprintf(fout_failure, "[NON_STANDARD_HASH: %s] %s", all_results[i].output_hex_str, all_results[i].original_line);
            }
            // 確保每行以換行符結尾
            if (all_results[i].status != SUCCESS_STANDARD_HASH &&
                strlen(all_results[i].original_line) > 0 &&
                all_results[i].original_line[strlen(all_results[i].original_line)-1] != '\n') {
                fprintf(fout_failure, "\n");
            }
        }

        fclose(fout_success);
        fclose(fout_failure);

        printf("Total  quantity: %zu\n", count);
        printf("Hash160 Success: %zu (Deduplicated and sorted)\n", standard_hash_count);
        printf("Hash160  failed: %zu\n", non_standard_or_failed_count);
    }

cleanup:
    // 清理所有動態分配的內存
    for (size_t i = 0; i < count; i++) {
        free(lines[i]);
        if (all_results[i].original_line) {
            free(all_results[i].original_line);
        }
    }
    free(lines);
    free(all_results);
    free(standard_hashes_collection);
    free(threads);
    free(thread_data);

    return 0;
}
