# Compiler
CC = gcc

# Compilation Flags
CFLAGS = -Wall -Wextra -O2

# Linker Flags
LDFLAGS = -lpthread -lssl -lcrypto

# Target Executable Name
TARGET = universal_decode

# List of Source Files
SRCS = universal_decode.c base58_nocheck.c segwit_addr.c

# List of Header Files
HDRS = base58_nocheck.h segwit_addr.h

# Corresponding Object Files
OBJS = $(SRCS:.c=.o)

# Default Target
all: $(TARGET)

# Link object files to create the executable and remove .o files
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
	rm -f $(OBJS)

# Compile each source file into an object file
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up compiled files
clean:
	rm -f $(TARGET) $(OBJS)

# Phony Targets
.PHONY: all clean
