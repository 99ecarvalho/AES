# Makefile for AES-256-CTR benchmark

# Compiler and flags
CC = gcc
CFLAGS = -std=c99 -O3 -march=native -Wall -Wextra
LIBS = -lssl -lcrypto
TARGET = aes
SOURCE = aes.c

# Default target
all: $(TARGET)

# Build the executable
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

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
	@echo "Testing OpenSSL EVP mode..."
	./$(TARGET) --mode evp --size 1048576 --iters 5
	@echo "Testing OpenSSL EVP software-only mode..."
	./$(TARGET) --mode evp-soft --size 1048576 --iters 5
	@echo "Testing AF_ALG mode..."
	./$(TARGET) --mode afalg --size 1048576 --iters 5

# Comprehensive benchmark comparison
benchmark: $(TARGET)
	@echo "=========================================="
	@echo "AES-256-CTR Performance Comparison"
	@echo "Size: 1MB, Iterations: 10"
	@echo "=========================================="
	@echo "1. Pure Software Implementation:"
	@./$(TARGET) --mode soft --size 1048576 --iters 10
	@echo ""
	@echo "2. AES-NI Hardware Acceleration:"
	@./$(TARGET) --mode aesni --size 1048576 --iters 10
	@echo ""
	@echo "3. OpenSSL EVP (Auto Detection):"
	@./$(TARGET) --mode evp --size 1048576 --iters 10
	@echo ""
	@echo "4. OpenSSL EVP (Software Only):"
	@./$(TARGET) --mode evp-soft --size 1048576 --iters 10
	@echo ""
	@echo "5. Linux Kernel AF_ALG:"
	@./$(TARGET) --mode afalg --size 1048576 --iters 10
	@echo "=========================================="

# Python analysis with multiple sizes and visualization
analysis: $(TARGET)
	@echo "Running comprehensive benchmark analysis..."
	@echo "This will test multiple data sizes and generate plots."
	@if [ ! -d "venv" ]; then \
		echo "Virtual environment not found. Run 'make deps' first."; \
		exit 1; \
	fi
	@bash -c "source venv/bin/activate && python3 benchmark_analysis.py"

# Quick test with smaller dataset
quick-analysis: $(TARGET)
	@echo "Running quick benchmark analysis (3 sizes, fewer iterations)..."
	@if [ ! -d "venv" ]; then \
		echo "Virtual environment not found. Run 'make deps' first."; \
		exit 1; \
	fi
	@bash -c "source venv/bin/activate && python3 quick_test.py"

# Install Python dependencies
deps:
	@echo "Installing Python dependencies..."
	@./install_deps.sh

# Help target
help:
	@echo "Available targets:"
	@echo "  all            - Build the AES benchmark (default)"
	@echo "  clean          - Remove build artifacts"
	@echo "  debug          - Build with debug symbols"
	@echo "  run            - Run the program with default parameters"
	@echo "  test           - Run tests with different modes"
	@echo "  benchmark      - Quick performance comparison"
	@echo "  analysis       - Comprehensive analysis with plots (requires Python)"
	@echo "  quick-analysis - Quick analysis with 3 sizes (faster)"
	@echo "  deps           - Install Python dependencies for analysis"
	@echo "  install        - Install to /usr/local/bin"
	@echo "  uninstall      - Remove from /usr/local/bin"
	@echo "  help           - Show this help message"

# Phony targets
.PHONY: all clean debug run test benchmark analysis quick-analysis deps install uninstall help