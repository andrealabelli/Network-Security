# Network Security Visualization (TON_IoT)

This project visualizes the **TON_IoT Train/Test Network** dataset from Kaggle. It generates:

- Overall protocol distribution
- **TCP flooding** view using suspicious vs. non-suspicious connection states
- **UDP flooding** view using mean src/dst packets and bytes
- Attack comparisons (e.g., ransomware vs xss) using mean source packets

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python network_security_analysis.py \
  --input /path/to/TON_IoT_Train_Test_Network.csv \
  --output outputs \
  --top-attacks 10
```

The script saves plots as PNG files in the output directory.
