---

## 📌 Project Overview | NSSECU3 – S13 | Mini Project 2

This project focuses on **Malware Forensics** through **file system analysis and file type detection** using **magic number signatures**. The main objective is to detect the **true file types** of unknown and extensionless files from a mounted disk image, simulating real-world malware investigation scenarios.

This implementation uses **JSON-based file signature rules**, and the scanning logic is developed using **Python**. The project also includes **hashing, classification, grouping, and CSV reporting**.

---

## 🎯 Objectives

* Mount and analyze a disk image containing suspicious files
* Detect file types using **magic numbers**
* Generate **MD5 and SHA-1 hashes**
* Group detected file types
* Output forensic results into **CSV format**
* Demonstrate **code design, diagrams, and flowcharts**

---

## 🛠 Tools & Technologies Used

* **Operating System:** Windows

* **Disk Image Mounting:** Arsenal Image Mounter (AIM)

* **Programming Language:** Python 3

* **Libraries:**

  * `hashlib` – cryptographic hashing
  * `json` – rule parsing
  * `os`, `csv`, `sys` – filesystem traversal and output

* **AI Tools Used:**

  * ChatGPT
  * DeepSeek

---

## ⚙️ System Workflow

1. Copy 220 files into the victim machine’s Documents folder
2. Create a disk image of the system
3. Mount the disk image using Arsenal Image Mounter (AIM)
4. Scan the mounted image using the Python scanner
5. Detect file types using JSON-based magic number rules
6. Generate hashes and classify detected files
7. Export forensic results to CSV

---

## 🧩 System Architecture

**Main Components:**

* `mp2_signature.py` – File type detection engine
* `mp2_scanner.py` – File scanner, hashing, and report generator
* `mp2_rules.json` – JSON-based file signature rules

---

## 🔍 Detection Logic

* Reads the **first 50 bytes** of each file
* Compares against **JSON-defined magic numbers**
* Matches longest patterns first
* Applies file size tolerance for accuracy
* Returns detected file type

---

## 📊 Output

The scanner generates a CSV file containing:

* File Name
* MD5 Hash
* SHA-1 Hash
* Directory Location
* Detected File Type
* Magic Number Bytes

---

## 📐 Code Design, Diagrams & Flowcharts

This project includes:

* **Code Design:** Modular detection and scanning logic
* **Process Diagrams:** Overall forensic workflow phases
* **Flowcharts:** File scanning and detection decision logic

These are documented in the submitted report.

---

## 👨‍🏫 NIS_S13_05

**Ivan Antonio T. Alvarez | **
**Joshua Benedict B. Co | **
**Andrei Zarmin D. De Jesus | **
**Reyvin Matthew T. Tan**

---
✅ **Flowchart diagrams (PNG / PDF)**
✅ **Formal documentation format**
✅ **Cover page + title formatting**

Just say 😄
