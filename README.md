# Project Overview
**Universal Decode**

Universal Decode is an efficient multithreaded command-line tool designed to decode various cryptocurrency addresses (such as Bitcoin BTC, Bitcoin Cash BCH, Litecoin LTC, Bitcoin Gold BTG, etc.) and extract their underlying `hash160` values. `hash160` is a commonly used cryptographic hash employed in generating the core part of cryptocurrency addresses.

# Features
- **Support for Multiple Address Formats**: Supports various mainstream cryptocurrency address formats including Base58, CashAddr (Bech32), SegWit, and more.
- **Efficient Multithreading**: Utilizes POSIX threads (pthreads) to enable parallel processing, accelerating the decoding speed for large-scale address decoding.
- **Memory Optimization**: Dynamically allocates and releases memory to ensure stability when handling large amounts of data.
- **Error Handling and Statistics**: Detects errors during the decoding and extraction process, and provides statistics on the number of successful and failed decodings.
- **Flexible Command-Line Parameters**: Supports specifying input files, output files, and the number of threads to meet different requirements.

# Project Structure
```
universal_decode/
├── universal_decode.c       // Main program file
├── segwit_addr.c            // Implements SegWit address decoding
├── base58_nocheck.c         // Implements Base58 address decoding (no checksum)
├── segwit_addr.h            // SegWit address decoding function declarations
├── base58_nocheck.h         // Base58 address decoding function declarations
├── README.md                // Project documentation
├── LICENSE                  // License file
└── Makefile                 // Makefile for compilation
```

# Compilation and Usage

## Requirements
- **Operating System**: Linux (e.g., Debian/Ubuntu)
- **Compiler**: GCC (supports C99 standard)
- **Dependencies**: POSIX thread library (`pthreads`)

## Obtaining the Source Code
Place all relevant source code files (`universal_decode.c`, `segwit_addr.c`, `base58_nocheck.c`, `segwit_addr.h`, `base58_nocheck.h`) in the same directory, for example, `universal_decode/`.

## Compilation

### Using Make
```bash
make
```

### Or, navigate to the project directory in the terminal and run:
```bash
gcc -o universal_decode universal_decode.c segwit_addr.c base58_nocheck.c -lpthread -Wall
```
- `-o universal_decode`: Specifies the output executable file name as `universal_decode`.
- `-lpthread`: Links the POSIX thread library.
- `-Wall`: Enables all compiler warnings, helping to identify potential issues.

### Clean and Recompile
```bash
make clean
```
```bash
###Free access to the world's richest address rankings

http://addresses.loyce.club/

https://blockchair.com/dumps

grep -o -E '1[a-zA-Z0-9]{25,34}' Bitcoin_addresses_March_01_2025.tsv > bitcoin_addresses.txt

grep -o -E 't[13][1-9A-HJ-NP-Za-km-z]{33,34}' blockchair_zcash_addresses_latest.tsv > zcash_addresses

grep -o -E '([LM][1-9A-HJ-NP-Za-km-z]{33}|ltc1[02-9ac-hj-np-z]{39,59})' blockchair_litecoin_addresses_latest.tsv > litecoin_addresses

grep -o -E '([DA9][1-9A-HJ-NP-Za-km-z]{25,34})' blockchair_dogecoin_addresses_latest.tsv > dogecoin_addresses

grep -o -E '([X7][1-9A-HJ-NP-Za-km-z]{33})' blockchair_dash_addresses_latest.tsv > dash_addresses

grep -o -E '([qp][0-9a-z]{41})' blockchair_bitcoin-cash_addresses_latest.tsv > cash_addresses
                                   ---------------------------------          ---------------
                                   Download document data from the website  >  Extract plain text address
```
# Running
Use the following command format to run the program:
```bash
./universal_decode -f <input_file> -o <output_file> [-t <thread_count>]

- `-f <input_file>`: Specifies the input file containing cryptocurrency addresses, one address per line.
- `-o <output_file>`: Specifies the output file for the extracted `hash160` values, one `hash160` per line.
- `-t <thread_count>`: Optional, specifies the number of threads to use. Defaults to single-threaded. It is recommended to set this to the number of CPU cores on the system to optimize performance.

## Example:
```bash
./universal_decode -f input_addresses.txt -o output_hash160.txt -t 4
```

# Example and Validation

## Example Input File (`input_addresses.txt`)
```
19qZAgZM4dniNqwuYmQca7FBReTLGX9xyS
1PsfCHrCU3j8Y2eyPdSvfWMsk5H5pEm6j9
3FQGSwS6fiqLh7Uy4pAdYahYBY8TUxwwt5
bc1qvrha9apveexwukwvd8xa2nrknnqvqu8nd5a644
bc1pmy787t5td4sn8eayl97apvclzs6sju5sa73c690e2u05t8c53m6sk2n8zs
mpMWTjeKsfDy9xRXGLNzQ2TWHe43AyFPbA
n4PcVLwBH5APK98b7CRJVRaCc4sngyV7Kv
2N6xUWgN8HBLgtu7WjwnWAXgoPtLdEi8Vdr
tb1qvrha9apveexwukwvd8xa2nrknnqvqu8n8jxfwx
tb1pmy787t5td4sn8eayl97apvclzs6sju5sa73c690e2u05t8c53m6spz9gcl
qpswl5h59n8yemjee35um42vw6wvpsrs7v5urjyua2
qrawwuke343qt8j2yhhyzwht758kkk02tv0erlat2d
19qZAgZM4dniNqwuYmQca7FBReTLGX9xyS
1PsfCHrCU3j8Y2eyPdSvfWMsk5H5pEm6j9
GSgUaotJ3VQ1TKFCUi4izsb5LpFBDL8fUB
GgiacRB9SuLRcVxGKa736GhmfF4vmh4TpK
AVV8AtoHSyB7QuzXWNANGqbhWcmSFEc3Vi
btg1qvrha9apveexwukwvd8xa2nrknnqvqu8nmamlqa
LU4WRtsB9J2mdee4iuPur8JwdrpcLrUjD1
Li6cTWA2YhyBnqM8ZmSDwXRdxHeMuf9A56
MMcQkpr4cqgmVcksAh9yNDwwWEiuQW7pVB
ltc1qvrha9apveexwukwvd8xa2nrknnqvqu8nfg87d9
ltc1pmy787t5td4sn8eayl97apvclzs6sju5sa73c690e2u05t8c53m6s4wahc4
DDyehwVzN3gzur8WHMQB7sQnJnBdco8u1y
DU1kjYnqmTdR52qa8DSVDGXUdD1PBXiqb5
XjXPzwDF2M1JXnYVQeiqRdvyFz32GiBAAW
XyZW2YW6RkwigyFZFWm9X33faQrmpFXrZa
t1SiAB1yV2xaJyUzoVCDjhvM6gJeR39MVFR
t1gkGCdGLSNWj8fhsL4G3oKTnzjUAbnx5s9
xH9C4ZPpLMGkRE3muF3H1HXxekkZaoCnbb
xXBJ6AgfjmDAaQkqk75b6geeyBaKF19v2F
0xcacCF59299921f40D087760032a4E720aF5b68FC
```

## Run Command
```bash
./universal_decode -f input_addresses.txt -o output_hash160.txt -t 4
```

## Console Output
```
Total processed: 32
Successfully decoded: 32
Failed to decode: 0
```

## Output File (`output_hash160.txt`)
```
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
9666d04e8867ce00ff5fb37ba8d413feb9ef2ef6
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
d93c7f2e8b6d6133e7a4f97dd0b31f1435097290efa38d15f9571f459f148ef5
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
9666d04e8867ce00ff5fb37ba8d413feb9ef2ef6
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
d93c7f2e8b6d6133e7a4f97dd0b31f1435097290efa38d15f9571f459f148ef5
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
9666d04e8867ce00ff5fb37ba8d413feb9ef2ef6
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
9666d04e8867ce00ff5fb37ba8d413feb9ef2ef6
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
d93c7f2e8b6d6133e7a4f97dd0b31f1435097290efa38d15f9571f459f148ef5
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
b860efd2f42cce4cee59cc69cdd54c769cc0c070
b8fae772d98d62059e4a25ee413aebf50f6b59ea
60efd2f42cce4cee59cc69cdd54c769cc0c070f3
fae772d98d62059e4a25ee413aebf50f6b59ea5b
caccf59299921f40d087760032a4e720af5b68fc
```

# Notes
- For BCH addresses, the `00` prefix of `hash160` has been correctly removed, extracting only the valid `hash160`.
- For SegWit and Hex-encoded addresses, `hash160` has been correctly extracted.
- For ETH addresses, only the `0x` prefix is removed, retaining the subsequent values for use in other programs.

# Dependencies
- **C Standard Library**: Used for basic input/output, string processing, and memory management.
- **POSIX Thread Library (`pthreads`)**: Used to implement multithreaded parallel processing.
- **Custom Decoding Functions**:
  - `segwit_addr_decode`: Used to decode SegWit addresses (Bech32 format).
  - `base58_decode_nocheck`: Used to decode Base58 addresses, skipping checksum verification.

# License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

# Contributing
Contributions are welcome! Please follow the steps below to participate:

# Sponsorship
If this project has been helpful to you, please consider sponsoring. It is the greatest support for me, and I am deeply grateful. Thank you.

- **BTC**: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
- **ETH**: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
- **DOGE**: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
- **TRX**: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

# Contact
If you have any questions, suggestions, or feedback, please feel free to contact us.

# Disclaimer
This tool is intended for educational and research purposes only. Users are responsible for any risks and liabilities arising from the use of this tool. The developers are not liable for any losses resulting from the use of this tool.
