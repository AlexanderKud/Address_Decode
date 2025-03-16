#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LEN 65536

void process_file(FILE *input, FILE *output) {
    char line[MAX_LINE_LEN];
    int line_num = 0;
    int successful_lines = 0;  // 新增：成功提取地址的行数

    while (fgets(line, sizeof(line), input)) {
        line_num++;

        line[strcspn(line, "\n")] = '\0';
        char *delim = strpbrk(line, " \t");
        if (delim) {
            *delim = '\0';
            fprintf(output, "%s\n", line);
            successful_lines++; // 新增：成功提取，计数器加 1
        } else {
            fprintf(stderr, "Warning: No delimiter found on line %d\n", line_num);
        }
    }

    printf("Total lines processed: %d\n", line_num);          // 新增：打印总行数
    printf("Successfully extracted addresses: %d\n", successful_lines); // 新增：打印成功提取的行数
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input-file> <output-file>\n", argv[0]);
        return 1;
    }

    FILE *input = fopen(argv[1], "r");
    if (!input) {
        perror("Error opening input file");
        return 2;
    }

    FILE *output = fopen(argv[2], "w");
    if (!output) {
        perror("Error opening output file");
        fclose(input);
        return 3;
    }

    process_file(input, output);

    fclose(input);
    fclose(output);
    return 0;
}
