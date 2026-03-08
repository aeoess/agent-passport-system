#!/usr/bin/env python3
"""
AEOESS Autoresearch Results Visualizer
Reads results.jsonl and prints a Karpathy-style dot chart + summary.
"""

import json
import sys
from pathlib import Path

def main():
    results_file = Path(__file__).parent / "results.jsonl"
    if not results_file.exists():
        print("No results.jsonl found. Run autoresearch.sh first.")
        sys.exit(1)
    
    results = []
    with open(results_file) as f:
        for line in f:
            line = line.strip()
            if line:
                results.append(json.loads(line))
    
    if not results:
        print("No results yet.")
        sys.exit(0)
    
    # Dot chart (like Karpathy's scatter plot, but terminal-friendly)
    print("AEOESS Autoresearch Progress")
    print("=" * 60)
    print()
    
    # Show dots: ● = kept, ★ = bug found, · = discarded
    dots = []
    test_counts = []
    for r in results:
        if r["result"] == "BUG_FOUND":
            dots.append("★")
        elif r["result"] == "KEPT":
            dots.append("●")
        else:
            dots.append("·")
        test_counts.append(r["tests"])
    
    # Print dots in rows of 50
    for i in range(0, len(dots), 50):
        row = dots[i:i+50]
        row_num = f"{i+1:3d}-{min(i+50, len(dots)):3d}"
        print(f"  {row_num} {''.join(row)}")
    
    print()
    print(f"  ● = kept ({sum(1 for d in dots if d == '●')})")
    print(f"  ★ = bug found ({sum(1 for d in dots if d == '★')})")
    print(f"  · = discarded ({sum(1 for d in dots if d == '·')})")
    
    # Summary
    kept = sum(1 for r in results if r["result"] == "KEPT")
    bugs = sum(1 for r in results if r["result"] == "BUG_FOUND")
    discarded = sum(1 for r in results if r["result"] == "DISCARDED")
    
    print()
    print("─" * 60)
    print(f"  Iterations:    {len(results)}")
    print(f"  Kept:          {kept}")
    print(f"  Bugs found:    {bugs}")
    print(f"  Discarded:     {discarded}")
    print(f"  Keep rate:     {(kept + bugs) / len(results) * 100:.1f}%")
    print(f"  Start tests:   {results[0]['tests']}")
    print(f"  Final tests:   {results[-1]['tests']}")
    print(f"  Tests added:   {results[-1]['tests'] - results[0]['tests']}")
    print(f"  First run:     {results[0]['timestamp']}")
    print(f"  Last run:      {results[-1]['timestamp']}")
    print("─" * 60)
    
    # Test count progression
    print()
    print("Test Count Progression:")
    min_t = min(test_counts)
    max_t = max(test_counts)
    width = 40
    for i, (r, tc) in enumerate(zip(results, test_counts)):
        if max_t > min_t:
            bar_len = int((tc - min_t) / (max_t - min_t) * width)
        else:
            bar_len = width
        marker = "★" if r["result"] == "BUG_FOUND" else "●" if r["result"] == "KEPT" else " "
        if (i + 1) % 5 == 0 or i == 0 or i == len(results) - 1:
            print(f"  {i+1:3d} {'█' * bar_len}{'░' * (width - bar_len)} {tc} {marker}")

if __name__ == "__main__":
    main()
