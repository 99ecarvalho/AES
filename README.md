# AES-256-CTR Benchmarks

This repository explores the performance of AES-256 in counter (CTR) mode on
x86-64 Linux, with particular attention to Intel Atom E3845 (Silvermont). It
contains a multi-backend C benchmark, an Atom-focused implementation, assembly
experiments, and scripts for collecting and plotting measurements.

## What was built

- [`aes.c`](aes.c) benchmarks seven paths: portable C (`soft`), direct AES-NI
  (`aesni`), two optimized AES-NI variants (`aesni-native`, `aesni-atom`),
  OpenSSL EVP (`evp`, `evp-soft`), and the Linux AF_ALG crypto interface
  (`afalg`). They use the same command-line interface for comparisons across
  input sizes and iteration counts.
- [`aesfinal.c`](aesfinal.c) is a separate Atom-oriented AES-NI/CTR benchmark
  built by [`Makefile_aesfinal`](Makefile_aesfinal). It experiments with
  precomputed round keys, unrolled rounds, and two-block processing.
- [`assembly/`](assembly/) contains inline and standalone assembly experiments
  and a separate build file. See the [assembly notes](assembly/README_ASSEMBLY.md)
  for their current limitations.
- [`benchmark_analysis.py`](benchmark_analysis.py) and
  [`quick_test.py`](quick_test.py) run the main benchmark at multiple sizes and
  produce JSON results and PNG/PDF plots. The tracked
  [`quick_test_results.json`](quick_test_results.json) and
  [`quick_test_plots/`](quick_test_plots/) are example measurements and charts.

## Build and run

Requirements: x86-64 Linux, a C99-capable GCC, Make, and OpenSSL development
headers and libraries. AES-NI modes require a CPU with AES-NI; AF_ALG requires
Linux kernel crypto support. The separate Atom-oriented build uses static
linking and requires the corresponding static toolchain libraries.

```sh
make
./aes --mode soft --size 1048576 --iters 10
./aes --mode evp --size 1048576 --iters 10
make benchmark

make -f Makefile_aesfinal
./aesfinal --size 1048576 --iters 10
```

Run `./aes --help` or `./aesfinal --help` for their options. `make test` runs
all seven main modes, including the hardware- and kernel-dependent ones.

## Analysis

Python 3 with NumPy, pandas, Matplotlib, and seaborn is needed for plots. The
repository's `make deps` target installs these into its `venv/` environment.
After building `aes`, run:

```sh
make deps
make quick-analysis
# or, for a larger set of measurements:
make analysis
```

`make quick-analysis` writes `quick_test_results.json` and `quick_test_plots/`;
`make analysis` writes `benchmark_results.json` and `benchmark_plots/`.
Generated measurements depend on the CPU, compiler, kernel, OpenSSL build, and
run conditions; do not treat the checked-in charts or throughput figures as
portable performance guarantees. These programs are benchmark experiments,
not a validated cryptographic library or a substitute for correctness and
security testing before production use.

For more detail, see the [main benchmark notes](docs/README.md) and the
[Atom-focused implementation notes](docs/README_AESFINAL.md).