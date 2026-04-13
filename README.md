#  Hardware Trojan Detection on Verilog Netlists

##  Overview

This project implements a Python-based system to detect **hardware Trojans** in gate-level Verilog netlists. It analyzes circuit structure and identifies anomalies that may indicate malicious modifications.

---

## Features

* Detects **trigger-based and always-active Trojans**
* Parses Verilog netlists
* Performs **structural anomaly analysis**
* Generates:

  * Anomaly score
  * Suspicious gates
  * Trojan classification

---

##  Tech Stack

* Python 3
* Verilog (test circuits)
* PyTest (testing)

---

##  Project Structure

```
hardware-trojan-detection/
├── trojan_detector.py
├── netlists/
├── tests/
├── results/
└── requirements.txt
```

---

## Installation

```bash
pip install -r requirements.txt
```

---

## How to Run

### Run single file:

```bash
python trojan_detector.py netlists/trojan_infected.v
```

### Run all circuits:

```bash
python trojan_detector.py --batch
```

---

## Run Tests

```bash
python -m pytest tests -v
```

---

## Example Output

* Total gates analyzed
* Suspicious nodes detected
* Anomaly score
* Trojan verdict (Clean / Suspicious / Infected)

---

## Applications

* Hardware security research
* Trojan detection in IC design
* Pre-silicon verification

---

## Future Improvements

* Machine learning-based detection
* Integration with FPGA tools
* Visualization of circuit graphs

---

## Author

Mithilesh Subramani 
