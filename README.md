# AES-256-CTR Performance Benchmark

A comprehensive benchmark suite for comparing different AES-256-CTR implementations including pure software, AES-NI hardware acceleration, OpenSSL EVP, and Linux kernel AF_ALG.

## 📋 Available Implementations

This benchmark suite includes 7 different AES-256-CTR implementations:

1. **soft** - Pure software implementation (portable)
2. **aesni** - AES-NI hardware acceleration (x86 processors)  
3. **aesni-native** - Native AES-NI intrinsics (optimized)
4. **aesni-atom** - Atom/Silvermont optimized (2-way parallelism)
5. **evp** - OpenSSL EVP interface (auto-detection)
6. **evp-soft** - OpenSSL EVP software-only mode
7. **afalg** - Linux kernel crypto API (AF_ALG)

- **Python Analysis Suite:**
  - Automated benchmarking across multiple data sizes
  - Statistical analysis and visualization
  - Box plots, performance comparisons, heatmaps
  - Export to PDF and PNG formats

## Quick Start

### 1. Build the benchmark
```bash
make
```

### 2. Run basic tests
```bash
# Quick performance comparison
make benchmark

# Test all modes
make test

# Run single mode
./aes --mode evp --size 1048576 --iters 10
```

### 3. Install Python dependencies and run analysis
```bash
# Install Python virtual environment and dependencies
make deps

# Quick analysis (3 sizes, faster)
make quick-analysis

# Comprehensive analysis (8 sizes, more thorough)
make analysis
```

## Usage

### Command Line Options

```text
./aes --mode {soft|aesni|aesni-native|evp|evp-soft|afalg} [options]

Options:
  --mode MODE     Implementation to benchmark
  --size BYTES    Data size in bytes (default: 1048576)
  --iters N       Number of iterations (default: 10)
  --debug N       Debug verbosity level (default: 0)
  --help          Show help message
```

### Available Make Targets
```
make all            # Build the benchmark (default)
make test           # Run tests with different modes  
make benchmark      # Quick performance comparison
make deps           # Install Python dependencies
make quick-analysis # Quick analysis (3 sizes)
make analysis       # Comprehensive analysis (8 sizes)
make clean          # Remove build artifacts
make help           # Show all available targets
```

## Python Analysis

The Python analysis suite generates:

1. **Throughput Box Plots** - Performance distribution across data sizes
2. **Cycles per Byte Plots** - Efficiency comparison 
3. **Performance vs Size Charts** - Scaling behavior analysis
4. **Performance Heatmaps** - Relative performance ratios
5. **Summary Statistics** - Detailed statistical analysis

### Output Files
- `benchmark_plots/` - Generated visualizations (PNG/PDF)
- `benchmark_results.json` - Raw benchmark data
- `summary_statistics.csv` - Statistical summary

## Performance Results (Example)

Typical performance on modern x86_64 hardware:

| Mode         | Throughput (MB/s) | Cycles/Byte | Description |
|--------------|-------------------|-------------|-------------|
| evp-soft     | ~4,525            | ~0.64       | OpenSSL software |
| evp          | ~3,978            | ~0.73       | OpenSSL optimized |
| aesni-atom   | ~3,537            | ~0.82       | Atom/Silvermont opt |
| afalg        | ~1,886            | ~1.54       | Linux kernel |
| aesni-native | ~953              | ~3.04       | Native AES-NI |
| aesni        | ~848              | ~3.42       | Direct AES-NI |
| soft         | ~78               | ~37.2       | Pure software |

## Requirements

### Build Dependencies
- GCC with C99 support
- OpenSSL development libraries (`libssl-dev`)
- Linux kernel with AF_ALG support

### Analysis Dependencies (Auto-installed)
- Python 3.7+
- matplotlib
- seaborn  
- pandas
- numpy

## Installation

### Ubuntu/Debian
```bash
# Install build dependencies
sudo apt update
sudo apt install build-essential libssl-dev python3-full python3-venv

# Clone and build
git clone <repository>
cd AES
make deps  # Sets up Python environment
make       # Builds the benchmark
```

## Contributing

Feel free to submit issues, feature requests, or pull requests. Areas for improvement:

- Additional cipher modes (GCM, CBC, etc.)
- ARM NEON optimizations
- Windows CryptoAPI support
- GPU acceleration benchmarks

## License

This project is released under the MIT License. See LICENSE file for details.

## Author

Created by Eduardo Correia <ecorreia@apliant.com.br>