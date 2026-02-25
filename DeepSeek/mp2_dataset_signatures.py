#!/usr/bin/env python3
"""
mp2_dataset_signatures.py

Generates unique signatures for each distinct file in the dataset.
Signature = size range (size ±50) + a byte prefix (from the start) that is
unique among all distinct files.

Usage: python mp2_dataset_signatures.py /path/to/dataset
"""

import os
import json
import hashlib
import argparse
from collections import defaultdict


def get_file_hash(filepath, algo='md5'):
    """Compute hash of a file (used only internally to group duplicates)."""
    hash_func = hashlib.new(algo)
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def find_unique_prefix(filepath, other_files, start_len=4, max_len=4096):
    """
    Find the smallest prefix length (in bytes) such that the prefix of this file
    is different from the prefix of every other file in 'other_files' at the same length.
    Returns (prefix_hex, length) or (None, 0) if not found within max_len.
    """
    with open(filepath, 'rb') as f:
        data = f.read(max_len)
    if not data:
        return None, 0

    for l in range(start_len, min(max_len, len(data)) + 1):
        prefix = data[:l]
        unique = True
        for other in other_files:
            if other == filepath:
                continue
            with open(other, 'rb') as of:
                other_data = of.read(l)
                if len(other_data) == l and other_data == prefix:
                    unique = False
                    break
        if unique:
            return prefix.hex().upper(), l
    return None, 0


def main():
    parser = argparse.ArgumentParser(description="Generate unique file signatures from dataset.")
    parser.add_argument("dataset_folder", help="Path to the dataset folder")
    args = parser.parse_args()

    dataset = os.path.abspath(args.dataset_folder)
    if not os.path.isdir(dataset):
        print(f"Error: '{dataset}' is not a valid directory.", file=sys.stderr)
        sys.exit(1)

    # Collect all files and group by hash to identify duplicates
    files_by_hash = defaultdict(list)
    for root, dirs, files in os.walk(dataset):
        for f in files:
            path = os.path.join(root, f)
            if os.path.isfile(path):
                h = get_file_hash(path)
                files_by_hash[h].append(path)

    # Pick one representative per unique file content
    unique_files = [paths[0] for paths in files_by_hash.values()]

    # Generate signatures for each unique file
    signatures = []
    for i, rep in enumerate(unique_files):
        size = os.path.getsize(rep)
        # List of other unique files (excluding current)
        others = [p for j, p in enumerate(unique_files) if j != i]

        prefix_hex, length = find_unique_prefix(rep, others, start_len=4, max_len=1024)
        if prefix_hex is None:
            print(f"Warning: Could not find unique prefix for {rep} within 1024 bytes. "
                  "You may need to increase max_len or check for identical files.")
            continue

        signatures.append({
            "size_min": size - 50,
            "size_max": size + 50,
            "prefix_hex": prefix_hex,
            "prefix_len": length,
            # The following fields are for reference only, not used in scanning
            "representative": rep,
            "hash": h
        })

    # Save signatures to JSON
    with open("file_signatures.json", "w") as f:
        json.dump(signatures, f, indent=2)

    print(f"Generated signatures for {len(signatures)} unique files.")
    print("Saved to file_signatures.json")


if __name__ == "__main__":
    import sys
    main()