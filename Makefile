# Makefile for AES-256-CTR benchmark

# Compiler and flags
CC = gcc
CFLAGS = -std=c99 -O3 -march=native -Wall -Wextra
TARGET = aes
SOURCE = aes.c

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

# Clean build artifacts
clean:
	rm -f $(TARGET)

# Install target (optional)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Uninstall target (optional)
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Run the program with default parameters
run: $(TARGET)
	./$(TARGET)

# Run tests with different modes
test: $(TARGET)
	@echo "Testing software mode..."
	./$(TARGET) --mode soft --size 1048576 --iters 5
	@echo "Testing AES-NI mode..."
	./$(TARGET) --mode aesni --size 1048576 --iters 5
	@echo "Testing AF_ALG mode..."
	./$(TARGET) --mode afalg --size 1048576 --iters 5

# Help target
help:
	@echo "Available targets:"
	@echo "  all      - Build the AES benchmark (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  debug    - Build with debug symbols"
	@echo "  run      - Run the program with default parameters"
	@echo "  test     - Run tests with different modes"
	@echo "  install  - Install to /usr/local/bin"
	@echo "  uninstall- Remove from /usr/local/bin"
	@echo "  help     - Show this help message"

# Phony targets
.PHONY: all clean debug run test install uninstall help