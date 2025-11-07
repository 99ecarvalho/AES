# Makefile for AES-256-CTR benchmark

# Compiler and flags
CC = gcc
CFLAGS_BASE = -std=c99 -O3 -Wall -Wextra
CFLAGS_NATIVE = $(CFLAGS_BASE) -march=native
CFLAGS_ATOM = -std=c99 -O3 -march=silvermont -mtune=silvermont -maes -flto -fomit-frame-pointer -funroll-loops -lrt
CFLAGS_GENERIC = $(CFLAGS_BASE) -march=x86-64 -maes -msse4.1 -msse4.2
LIBS = -lssl -lcrypto
TARGET = aes
SOURCE = aes.c

# Default target (native optimization)
all: $(TARGET)

# Build the executable with native optimization
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS_NATIVE) -o $(TARGET) $(SOURCE) $(LIBS)

# Build with static linking (native)
static: $(SOURCE)
	$(CC) $(CFLAGS_NATIVE) -static -o $(TARGET)-static $(SOURCE) $(LIBS)

# Build for Atom processors (E3845 compatible)
atom: $(SOURCE)
	$(CC) $(CFLAGS_ATOM) -o $(TARGET)-atom $(SOURCE) $(LIBS)

# Build static for Atom processors
atom-static: $(SOURCE)
	$(CC) $(CFLAGS_ATOM) -static -o $(TARGET)-atom-static $(SOURCE) $(LIBS)

# Build generic x86_64 (maximum compatibility)
generic: $(SOURCE)
	$(CC) $(CFLAGS_GENERIC) -o $(TARGET)-generic $(SOURCE) $(LIBS)

# Build static generic x86_64
generic-static: $(SOURCE)
	$(CC) $(CFLAGS_GENERIC) -static -o $(TARGET)-generic-static $(SOURCE) $(LIBS)

# Test compatibility of built executables
test-compat:
	@echo "Testing Compatibility of Built Executables:"
	@echo "==========================================="
	@for exe in aes-atom-static aes-generic-static; do \
		if [ -f $$exe ]; then \
			echo "Testing $$exe:"; \
			echo "  Architecture: $$(file $$exe | cut -d',' -f2-)"; \
			echo "  Size: $$(ls -lh $$exe | awk '{print $$5}')"; \
			echo "  Soft mode test:"; \
			./$$exe --mode soft --size 65536 --iters 1 | head -1; \
			echo ""; \
		fi; \
	done
	@echo "Recommended for E3845: ./aes-atom-static"
	@echo "For maximum compatibility: ./aes-generic-static"

# Show build information
info:
	@echo "Build Information:"
	@echo "=================="
	@for target in $(TARGET) $(TARGET)-static $(TARGET)-atom $(TARGET)-atom-static $(TARGET)-generic $(TARGET)-generic-static; do \
		if [ -f $$target ]; then \
			echo "Executable: $$target"; \
			ls -lh $$target; \
			echo "Dependencies:"; \
			ldd $$target 2>/dev/null || echo "  Statically linked (no dynamic dependencies)"; \
			echo ""; \
		fi; \
	done
	@echo "Available build targets:"
	@echo "  make all           - Native optimized (current CPU)"
	@echo "  make atom-static   - Atom E3845 compatible (recommended)"
	@echo "  make generic-static- Maximum compatibility x86_64"

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TARGET)-static $(TARGET)-atom $(TARGET)-atom-static $(TARGET)-generic $(TARGET)-generic-static

# Install target (optional)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Uninstall target (optional)
uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Debug build
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
	@echo "Testing AES-NI native mode..."
	./$(TARGET) --mode aesni-native --size 1048576 --iters 5
	@echo "Testing AES-NI Atom optimized mode..."
	./$(TARGET) --mode aesni-atom --size 1048576 --iters 5
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
	@echo "3. AES-NI Native Optimized:"
	@./$(TARGET) --mode aesni-native --size 1048576 --iters 10
	@echo ""
	@echo "4. AES-NI Atom/Silvermont Optimized:"
	@./$(TARGET) --mode aesni-atom --size 1048576 --iters 10
	@echo ""
	@echo "5. OpenSSL EVP (Auto Detection):"
	@./$(TARGET) --mode evp --size 1048576 --iters 10
	@echo ""
	@echo "6. OpenSSL EVP (Software Only):"
	@./$(TARGET) --mode evp-soft --size 1048576 --iters 10
	@echo ""
	@echo "7. Linux Kernel AF_ALG:"
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
	@echo "  all            - Build the AES benchmark (native optimized)"
	@echo "  atom           - Build for Atom processors (E3845)"
	@echo "  atom-static    - Build static for Atom processors"
	@echo "  generic        - Build generic x86_64 (max compatibility)"
	@echo "  generic-static - Build static generic x86_64"
	@echo "  static         - Build with static linking (native)"
	@echo "  info           - Show build information and dependencies"
	@echo "  clean          - Remove all build artifacts"
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
.PHONY: all atom atom-static generic generic-static static clean debug run test benchmark analysis quick-analysis deps install uninstall help info