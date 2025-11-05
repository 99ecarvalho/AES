#!/usr/bin/env python3
"""
AES-256-CTR Benchmark Analysis Tool

This script runs comprehensive benchmarks for different AES implementations
and generates box plots to visualize performance differences across various data sizes.

Author: GitHub Copilot Assistant
"""

# Try to import required packages, provide helpful error message if missing
try:
    import subprocess
    import re
    import pandas as pd
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    import sys
    import os
    import json
    from pathlib import Path
except ImportError as e:
    print(f"Error: Missing required Python package: {e}")
    print("\nTo install dependencies, run: make deps")
    print("This will create a virtual environment and install all required packages.")
    sys.exit(1)

class AESBenchmarkRunner:
    def __init__(self, executable_path="./aes"):
        self.executable_path = executable_path
        self.modes = ["soft", "aesni", "evp", "evp-soft", "afalg"]
        self.results = []
        
    def run_single_benchmark(self, mode, size, iterations=5):
        """Run a single benchmark and parse the results"""
        try:
            cmd = [self.executable_path, "--mode", mode, "--size", str(size), "--iters", str(iterations)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                print(f"Error running {mode} with size {size}: {result.stderr}")
                return None
                
            # Parse the output to extract throughput and cycles per byte
            output = result.stdout.strip()
            
            # Look for RESULTS line
            if "RESULTS" in output:
                # Extract throughput (MB/s) and cycles per byte
                throughput_match = re.search(r'throughput=([\d.]+) MB/s', output)
                cycles_match = re.search(r'cyc/byte=([\d.]+)', output)
                elapsed_match = re.search(r'elapsed=([\d.]+)s', output)
                
                if throughput_match and cycles_match and elapsed_match:
                    return {
                        'mode': mode,
                        'size': size,
                        'iterations': iterations,
                        'throughput_mbps': float(throughput_match.group(1)),
                        'cycles_per_byte': float(cycles_match.group(1)),
                        'elapsed_seconds': float(elapsed_match.group(1))
                    }
            
            print(f"Could not parse results for {mode} with size {size}")
            print(f"Output: {output}")
            return None
            
        except subprocess.TimeoutExpired:
            print(f"Timeout running {mode} with size {size}")
            return None
        except Exception as e:
            print(f"Exception running {mode} with size {size}: {e}")
            return None
    
    def run_comprehensive_benchmark(self, sizes=None, iterations=5, runs_per_test=3):
        """Run benchmarks across different sizes and modes"""
        if sizes is None:
            # Default sizes: 1KB to 16MB
            sizes = [1024, 4*1024, 16*1024, 64*1024, 256*1024, 1024*1024, 4*1024*1024, 16*1024*1024]
        
        total_tests = len(self.modes) * len(sizes) * runs_per_test
        current_test = 0
        
        print(f"Running {total_tests} benchmark tests...")
        print(f"Modes: {', '.join(self.modes)}")
        print(f"Sizes: {[f'{s//1024}KB' if s < 1024*1024 else f'{s//(1024*1024)}MB' for s in sizes]}")
        print(f"Iterations per test: {iterations}, Runs per configuration: {runs_per_test}")
        print("-" * 60)
        
        for mode in self.modes:
            print(f"\nTesting mode: {mode}")
            for size in sizes:
                size_str = f"{size//1024}KB" if size < 1024*1024 else f"{size//(1024*1024)}MB"
                print(f"  Size {size_str}: ", end="", flush=True)
                
                for run in range(runs_per_test):
                    current_test += 1
                    result = self.run_single_benchmark(mode, size, iterations)
                    
                    if result:
                        result['run'] = run + 1
                        self.results.append(result)
                        print("✓", end="", flush=True)
                    else:
                        print("✗", end="", flush=True)
                
                print(f" ({current_test}/{total_tests})")
        
        print(f"\nCompleted! Collected {len(self.results)} successful results out of {total_tests} tests.")
        
    def save_results(self, filename="benchmark_results.json"):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"Results saved to {filename}")
    
    def load_results(self, filename="benchmark_results.json"):
        """Load results from JSON file"""
        try:
            with open(filename, 'r') as f:
                self.results = json.load(f)
            print(f"Loaded {len(self.results)} results from {filename}")
            return True
        except FileNotFoundError:
            print(f"File {filename} not found")
            return False
    
    def create_visualizations(self, output_dir="benchmark_plots"):
        """Create comprehensive visualizations"""
        if not self.results:
            print("No results to visualize!")
            return
        
        # Create output directory
        Path(output_dir).mkdir(exist_ok=True)
        
        # Convert to DataFrame
        df = pd.DataFrame(self.results)
        
        # Add human-readable size column
        df['size_label'] = df['size'].apply(lambda x: f"{x//1024}KB" if x < 1024*1024 else f"{x//(1024*1024)}MB")
        
        # Set up plotting style
        plt.style.use('default')
        sns.set_palette("husl")
        
        # 1. Throughput Box Plot
        self._create_throughput_boxplot(df, output_dir)
        
        # 2. Cycles per Byte Box Plot  
        self._create_cycles_boxplot(df, output_dir)
        
        # 3. Performance vs Size Line Plot
        self._create_performance_vs_size(df, output_dir)
        
        # 4. Performance Ratio Heatmap
        self._create_performance_heatmap(df, output_dir)
        
        # 5. Summary Statistics Table
        self._create_summary_table(df, output_dir)
        
        print(f"All visualizations saved to {output_dir}/")
    
    def _create_throughput_boxplot(self, df, output_dir):
        """Create throughput box plot"""
        plt.figure(figsize=(14, 8))
        
        # Create box plot
        box_plot = sns.boxplot(data=df, x='size_label', y='throughput_mbps', hue='mode')
        
        plt.title('AES-256-CTR Throughput Comparison by Data Size', fontsize=16, fontweight='bold')
        plt.xlabel('Data Size', fontsize=12)
        plt.ylabel('Throughput (MB/s)', fontsize=12)
        plt.yscale('log')
        plt.grid(True, alpha=0.3)
        plt.legend(title='Implementation', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/throughput_boxplot.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{output_dir}/throughput_boxplot.pdf", bbox_inches='tight')
        plt.close()
        
    def _create_cycles_boxplot(self, df, output_dir):
        """Create cycles per byte box plot"""
        plt.figure(figsize=(14, 8))
        
        sns.boxplot(data=df, x='size_label', y='cycles_per_byte', hue='mode')
        
        plt.title('AES-256-CTR Cycles per Byte by Data Size', fontsize=16, fontweight='bold')
        plt.xlabel('Data Size', fontsize=12)
        plt.ylabel('Cycles per Byte', fontsize=12)
        plt.yscale('log')
        plt.grid(True, alpha=0.3)
        plt.legend(title='Implementation', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.xticks(rotation=45)
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/cycles_boxplot.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{output_dir}/cycles_boxplot.pdf", bbox_inches='tight')
        plt.close()
    
    def _create_performance_vs_size(self, df, output_dir):
        """Create performance vs size line plot"""
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 10))
        
        # Group by mode and size, calculate mean
        grouped = df.groupby(['mode', 'size']).agg({
            'throughput_mbps': ['mean', 'std'],
            'cycles_per_byte': ['mean', 'std']
        }).reset_index()
        
        # Flatten column names
        grouped.columns = ['mode', 'size', 'throughput_mean', 'throughput_std', 'cycles_mean', 'cycles_std']
        
        # Plot throughput
        for mode in df['mode'].unique():
            mode_data = grouped[grouped['mode'] == mode]
            ax1.errorbar(mode_data['size'], mode_data['throughput_mean'], 
                        yerr=mode_data['throughput_std'], 
                        label=mode, marker='o', capsize=5)
        
        ax1.set_xscale('log')
        ax1.set_yscale('log')
        ax1.set_xlabel('Data Size (bytes)')
        ax1.set_ylabel('Throughput (MB/s)')
        ax1.set_title('Throughput vs Data Size')
        ax1.grid(True, alpha=0.3)
        ax1.legend()
        
        # Plot cycles per byte
        for mode in df['mode'].unique():
            mode_data = grouped[grouped['mode'] == mode]
            ax2.errorbar(mode_data['size'], mode_data['cycles_mean'], 
                        yerr=mode_data['cycles_std'], 
                        label=mode, marker='s', capsize=5)
        
        ax2.set_xscale('log')
        ax2.set_yscale('log')
        ax2.set_xlabel('Data Size (bytes)')
        ax2.set_ylabel('Cycles per Byte')
        ax2.set_title('Cycles per Byte vs Data Size')
        ax2.grid(True, alpha=0.3)
        ax2.legend()
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/performance_vs_size.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{output_dir}/performance_vs_size.pdf", bbox_inches='tight')
        plt.close()
    
    def _create_performance_heatmap(self, df, output_dir):
        """Create performance ratio heatmap"""
        # Calculate relative performance (normalized to software implementation)
        pivot_data = df.groupby(['mode', 'size_label'])['throughput_mbps'].mean().reset_index()
        pivot_table = pivot_data.pivot(index='mode', columns='size_label', values='throughput_mbps')
        
        # Normalize to software implementation
        if 'soft' in pivot_table.index:
            soft_baseline = pivot_table.loc['soft']
            normalized_table = pivot_table.div(soft_baseline, axis=1)
        else:
            normalized_table = pivot_table
        
        plt.figure(figsize=(12, 6))
        sns.heatmap(normalized_table, annot=True, fmt='.1f', cmap='viridis', 
                   cbar_kws={'label': 'Performance Ratio (vs Software)'})
        
        plt.title('Performance Ratio Heatmap (Higher is Better)', fontsize=14, fontweight='bold')
        plt.xlabel('Data Size')
        plt.ylabel('Implementation')
        
        plt.tight_layout()
        plt.savefig(f"{output_dir}/performance_heatmap.png", dpi=300, bbox_inches='tight')
        plt.savefig(f"{output_dir}/performance_heatmap.pdf", bbox_inches='tight')
        plt.close()
    
    def _create_summary_table(self, df, output_dir):
        """Create summary statistics table"""
        # Calculate summary statistics
        summary = df.groupby('mode').agg({
            'throughput_mbps': ['mean', 'std', 'min', 'max'],
            'cycles_per_byte': ['mean', 'std', 'min', 'max']
        }).round(2)
        
        # Flatten column names
        summary.columns = [f"{col[1]}_{col[0]}" for col in summary.columns]
        
        # Save to CSV
        summary.to_csv(f"{output_dir}/summary_statistics.csv")
        
        # Create a nice formatted table plot
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.axis('tight')
        ax.axis('off')
        
        table = ax.table(cellText=summary.values,
                        rowLabels=summary.index,
                        colLabels=summary.columns,
                        cellLoc='center',
                        loc='center')
        
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1.2, 1.5)
        
        plt.title('Summary Statistics by Implementation', fontsize=14, fontweight='bold', pad=20)
        plt.savefig(f"{output_dir}/summary_table.png", dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"Summary statistics saved to {output_dir}/summary_statistics.csv")

def main():
    """Main function"""
    # Check if executable exists
    if not os.path.exists("./aes"):
        print("Error: ./aes executable not found!")
        print("Please compile the benchmark first: make")
        sys.exit(1)
    
    runner = AESBenchmarkRunner()
    
    # Check if we have cached results
    if runner.load_results():
        print("Using cached results. Delete benchmark_results.json to run fresh tests.")
    else:
        print("No cached results found. Running fresh benchmarks...")
        
        # Define test sizes (from 1KB to 16MB)
        sizes = [
            1024,           # 1KB
            4*1024,         # 4KB  
            16*1024,        # 16KB
            64*1024,        # 64KB
            256*1024,       # 256KB
            1024*1024,      # 1MB
            4*1024*1024,    # 4MB
            16*1024*1024,   # 16MB
        ]
        
        # Run benchmarks
        runner.run_comprehensive_benchmark(sizes=sizes, iterations=5, runs_per_test=3)
        
        # Save results
        runner.save_results()
    
    # Create visualizations
    runner.create_visualizations()
    
    # Print summary
    if runner.results:
        df = pd.DataFrame(runner.results)
        print("\n" + "="*60)
        print("BENCHMARK SUMMARY")
        print("="*60)
        
        avg_throughput = df.groupby('mode')['throughput_mbps'].mean().sort_values(ascending=False)
        print("\nAverage Throughput (MB/s):")
        for mode, throughput in avg_throughput.items():
            print(f"  {mode:10s}: {throughput:8.1f} MB/s")
        
        print(f"\nTotal tests completed: {len(runner.results)}")
        print(f"Visualizations saved to: benchmark_plots/")

if __name__ == "__main__":
    main()