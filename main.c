/*  https://github.com/8891689 
 *  Author: 8891689
 */
// gcc -O3 -lpthread -Wall -Wextra -march=native -static base58.c bech32.c cashaddr.c main.c sha256.c -o decode
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <pthread.h>
#include <errno.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "sha256.h"
#include "base58.h"
#include "bech32.h"
#include "cashaddr.h"

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
 * 2. 輔助函數：將十六進制字符串轉換為字節數組 
 * -------------------------------------------------------------------------*/
static int hex_to_bytes(const char *hex_str, unsigned char *bytes_out, size_t max_len) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) {
        return 0;
    }
    size_t bytes_len = len / 2;
    if (bytes_len > max_len) {
        return 0;
    }
    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int val;
        if (sscanf(hex_str + (i * 2), "%2x", &val) != 1) {
            return 0;
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
    size_t l = strlen(s);
    while(l > 0 && isspace((unsigned char)s[l-1])){
        s[--l] = 0;
    }
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
 * -------------------------------------------------------------------------*/
static int decode_address_general(const char *addr_str, unsigned char *out_bytes, size_t *out_len) {
    unsigned char temp_decoded_buf[64];
    size_t current_len = 0;
    int witver;

    uint8_t *b58_payload = base58_decode_check(addr_str, &current_len);
    if (b58_payload) {
        if (current_len >= 20) {
            memcpy(out_bytes, b58_payload + 1, 20);
            *out_len = 20;
            free(b58_payload);
            return 1;
        }
        free(b58_payload);
    }

    const char *hrps[] = {"bc", "tb", "ltc", "tltc", "btg", NULL};
    for (int i = 0; hrps[i] != NULL; ++i) {
        size_t segwit_prog_len_val = sizeof(temp_decoded_buf);
        if (segwit_addr_decode(addr_str, hrps[i], &witver, temp_decoded_buf, &segwit_prog_len_val)) {
            memcpy(out_bytes, temp_decoded_buf, segwit_prog_len_val);
            *out_len = segwit_prog_len_val;
            return 1;
        }
    }

    CashAddrResult cash_result;
    if (decode_cashaddr(addr_str, &cash_result) == 0) {
        current_len = hex_to_bytes(cash_result.hash160, out_bytes, 20);
        if (current_len == 20) {
            *out_len = 20;
            return 1;
        }
    }

    if (strncmp(addr_str, "0x", 2) == 0 || strncmp(addr_str, "0X", 2) == 0) {
        current_len = hex_to_bytes(addr_str + 2, out_bytes, sizeof(temp_decoded_buf));
    } else {
        current_len = hex_to_bytes(addr_str, out_bytes, sizeof(temp_decoded_buf));
    }

    if (current_len > 0) {
        *out_len = current_len;
        return 1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * 5. 线程相關結構和變量
 * -------------------------------------------------------------------------*/

#define DECODE_FAILED            -1
#define SUCCESS_NON_STANDARD_HASH 0
#define SUCCESS_STANDARD_HASH     1


typedef struct {
    char output_hex_str[65];     
    int status;                  
    size_t original_line_index;  
} ProcessedResult;

// ThreadData 結構用於傳遞給每個線程的數據 
typedef struct {
    char **lines;
    size_t start;
    size_t end;
    ProcessedResult *results;
} ThreadData;

// 線程處理函數
void* thread_process(void *arg)
{
    ThreadData *data = (ThreadData*)arg;
    for(size_t i = data->start; i < data->end; i++){
        char *full_line = data->lines[i];

        data->results[i].original_line_index = i;
        
        char address_part_buffer[512];

        char *tab_pos = strchr(full_line, '\t');
        if (tab_pos) {
            size_t addr_len = tab_pos - full_line;
            if (addr_len >= sizeof(address_part_buffer)) {
                data->results[i].status = DECODE_FAILED; 
                continue;
            }
            strncpy(address_part_buffer, full_line, addr_len);
            address_part_buffer[addr_len] = '\0';
        } else {
            strncpy(address_part_buffer, full_line, sizeof(address_part_buffer) - 1);
            address_part_buffer[sizeof(address_part_buffer) - 1] = '\0';
        }
        trim_whitespace(address_part_buffer);

        if (address_part_buffer[0] == '\0') {
            data->results[i].status = DECODE_FAILED;
            continue;
        }

        unsigned char extracted_bytes[64];
        size_t extracted_len = 0;

        if (decode_address_general(address_part_buffer, extracted_bytes, &extracted_len)) {
            if (extracted_len == 20) {
                data->results[i].status = SUCCESS_STANDARD_HASH;
                bytes_to_hex(extracted_bytes, 20, data->results[i].output_hex_str);
            } else {
                data->results[i].status = SUCCESS_NON_STANDARD_HASH;

                const size_t max_bytes_for_buffer = (sizeof(data->results[i].output_hex_str) - 1) / 2;
                
                size_t len_to_convert = extracted_len;

                if (len_to_convert > max_bytes_for_buffer) {
                    len_to_convert = max_bytes_for_buffer;
                }
                
                bytes_to_hex(extracted_bytes, len_to_convert, data->results[i].output_hex_str);

            }
        } else {
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

    char *input_source = NULL;
    char *output_base_name = "output";
    bool use_default_output_name = true;

    int thread_count = 4;
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
    if (thread_count == 0) thread_count = 1;

    if (argc == 2) {
        input_source = argv[1];
    } else if (argc == 4 && strcmp(argv[1], "-o") == 0) {
        output_base_name = argv[2];
        input_source = argv[3];
        use_default_output_name = false;
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
    size_t count = 0;
    bool is_file_input = false;

    FILE *fin = NULL;
    if (strcmp(input_source, "-") == 0) {
        fin = stdin;
        is_file_input = true;
    } else {
        fin = fopen(input_source, "r");
        if (fin) {
            is_file_input = true;
        } else {
            is_file_input = false;
            if (errno != ENOENT) {
                perror("無法打開輸入文件");
                return 1;
            }
        }
    }
    
    bool is_single_address_console_output_mode = !is_file_input && use_default_output_name;

    if (is_file_input) {
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

    ProcessedResult *all_results = (ProcessedResult*)calloc(count, sizeof(ProcessedResult));
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
          }
          free(lines); free(all_results); free(threads); free(thread_data);
          return 1;
       }
    }

    for(int i = 0; i < thread_count;i++){
      pthread_join(threads[i],NULL);
    }

    size_t standard_hash_count = 0;
    size_t non_standard_or_failed_count = 0;
    
    ProcessedResult *standard_hashes_collection = NULL;

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

                standard_hashes_collection[current_collection_idx] = all_results[i];
                current_collection_idx++;
            }
        }
    }

    if (standard_hash_count > 1) {
        qsort(standard_hashes_collection, standard_hash_count, sizeof(ProcessedResult), compare_hex_strings);
    }

    if (is_single_address_console_output_mode) {
        if (standard_hash_count > 0) {
            fprintf(stdout, "%s\n", standard_hashes_collection[0].output_hex_str);
        }
    } else {
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

        if (standard_hash_count > 0) {
            fprintf(fout_success, "%s\n", standard_hashes_collection[0].output_hex_str);
            for (size_t i = 1; i < standard_hash_count; ++i) {
                if (strcmp(standard_hashes_collection[i].output_hex_str, standard_hashes_collection[i-1].output_hex_str) != 0) {
                    fprintf(fout_success, "%s\n", standard_hashes_collection[i].output_hex_str);
                }
            }
        }

        for (size_t i = 0; i < count; i++) {

            size_t original_index = all_results[i].original_line_index;
            char* original_line = lines[original_index];

            if (all_results[i].status == DECODE_FAILED) {
                fprintf(fout_failure, "[DECODE_FAILED] %s", original_line);
            } else if (all_results[i].status == SUCCESS_NON_STANDARD_HASH) {
                fprintf(fout_failure, "[NON_STANDARD_HASH: %s] %s", all_results[i].output_hex_str, original_line);
            }

            if (all_results[i].status != SUCCESS_STANDARD_HASH &&
                strlen(original_line) > 0 &&
                original_line[strlen(original_line)-1] != '\n') {
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
    for (size_t i = 0; i < count; i++) {
        free(lines[i]);

    }
    free(lines);
    free(all_results);
    free(standard_hashes_collection);
    free(threads);
    free(thread_data);

    return 0;
}
