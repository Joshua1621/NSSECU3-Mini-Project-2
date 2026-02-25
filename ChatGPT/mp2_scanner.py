# -*- coding: utf-8 -*-
import os
import csv
import sys
import hashlib
from mp2_signature import detect_file_type

output_csv = "mp2_scan_results.csv"
results = []

# Custom display order
order = {
    "PDF": 1,
    "PNG": 2,
    "JPEG": 3,
    "ZIP": 4,
    "MP3": 5,
    "EXE": 6,
    "RIFF": 7,
    "PS_UTF8": 8,
    "BAT": 9,
    "ISO": 10,
    "Unknown": 99
}

rule_counts = {}
total_matched = 0
unknown_count = 0


def get_all_drives():
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(drive)
    return drives


def compute_hashes_and_first_bytes(file_path):
    """Return (md5_hex, sha1_hex, first_50_bytes) or (None, None, None) on error."""
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        first_50 = b''
        with open(file_path, "rb") as f:
            # Read first 50 bytes
            first_50 = f.read(50)
            md5.update(first_50)
            sha1.update(first_50)
            # Read the rest of the file in chunks
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
        return md5.hexdigest(), sha1.hexdigest(), first_50
    except Exception:
        return None, None, None


if len(sys.argv) > 1:
    scan_roots = [sys.argv[1]]
else:
    scan_roots = get_all_drives()

for root_path in scan_roots:
    print(f"Scanning: {root_path}")

    for root, dirs, files in os.walk(root_path):
        for filename in files:
            name, ext = os.path.splitext(filename)

            # Only extensionless files
            if ext != "":
                continue

            file_path = os.path.join(root, filename)

            md5_hash, sha1_hash, data = compute_hashes_and_first_bytes(file_path)
            if data is None:  # error reading file
                continue

            file_size = os.path.getsize(file_path)

            detected_ext = detect_file_type(data, file_size)

            # Skip unknown detections
            if detected_ext == "Unknown":
                unknown_count += 1
                continue

            # Format hex nicely
            magic_hex = data.hex().upper()
            magic_spaced = " ".join(magic_hex[i:i+2] for i in range(0, len(magic_hex), 2))

            # Get directory path (without filename)
            directory = os.path.dirname(file_path)

            results.append([
                filename,
                md5_hash,
                sha1_hash,
                directory,
                detected_ext,
                magic_spaced
            ])

            rule_counts[detected_ext] = rule_counts.get(detected_ext, 0) + 1
            total_matched += 1

# Sort results by custom order
results.sort(key=lambda x: order.get(x[4], 100))  # x[4] is File Type

# Save CSV
with open(output_csv, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)

    writer.writerow([
        "File Name",
        "Hash MD5",
        "Hash SHA1",
        "Directory Found",
        "File Type",
        "First 50-bytes of the Magic Numbers"
    ])

    writer.writerows(results)

print("\nScan complete. Results saved to", output_csv)

print("\n===== Detection Summary =====")
for rule_name in sorted(rule_counts, key=lambda x: order.get(x, 100)):
    print(f"{rule_name}: {rule_counts[rule_name]}")

print(f"\nTotal matched files: {total_matched}")
print(f"Unknown files: {unknown_count}")