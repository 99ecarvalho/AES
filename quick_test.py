#!/usr/bin/env python3
"""
Quick test of the benchmark analysis with smaller dataset
"""

import os
import sys

# Add check for virtual environment
def check_venv():
    if not os.path.exists("venv"):
        print("Virtual environment not found!")
        print("Please run 'make deps' first to set up dependencies.")
        sys.exit(1)

if __name__ == "__main__":
    check_venv()
    
    # Import the benchmark runner
    from benchmark_analysis import AESBenchmarkRunner
    
    print("Running quick benchmark test...")
    
    runner = AESBenchmarkRunner()
    
    # Test with smaller sizes and fewer iterations for quick testing
    test_sizes = [
        1024,        # 1KB
        64*1024,     # 64KB  
        1024*1024,   # 1MB
    ]
    
    print("Quick test with 3 sizes, 3 iterations each, 2 runs per test")
    runner.run_comprehensive_benchmark(sizes=test_sizes, iterations=3, runs_per_test=2)
    
    # Save and visualize
    runner.save_results("quick_test_results.json")
    runner.create_visualizations("quick_test_plots")
    
    print("\nQuick test completed!")
    print("Check quick_test_plots/ for generated visualizations.")