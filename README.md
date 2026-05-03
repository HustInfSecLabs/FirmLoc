# FirmLoc

FirmLoc is an LLM-agent-based framework for localizing vulnerabilities in firmware binaries.

---

## Prerequisites

The following tools must be installed and configured on your Linux system **before** proceeding. Due to licensing restrictions, they are **not** included in this repository and must be obtained independently:

- **IDA Pro** (ida / idat, 32-bit and 64-bit variants)
- **BinDiff**
- **Binwalk**

---

## Installation

### 1. Clone the repository

```bash
git clone https://anonymous.4open.science/r/VulnAgent-CLI-80FF/
cd FirmLoc
```

### 2. Create and activate the virtual environment

```bash
conda create -n firmloc python=3.11.11 -y
conda activate firmloc
pip install -r requirements.firmware.txt
```

---

## Configuration

All configuration is managed in `FirmLoc/config/config.ini`.

### LLM

```ini
[LLM]
default_key = GPT

[LLM.GPT]
model_name = gpt-4o-mini
api_key = sk-xxx
base_url =
```

### Binary Tools

```ini
[BINARY_TOOLS]
ida32_path = /path/to/ida
ida64_path = /path/to/ida
idat32_path = /path/to/idat
idat64_path = /path/to/idat
bindiff_path = /path/to/bindiff
```

### IDA Service

Navigate to the IDA service directory and start the service:

```bash
cd agent/IDAService/
python app.py
```

Then set the service URL in `config.ini`:

```ini
[IDA_SERVICE]
service_url = http://127.0.0.1:5000
```

---

## Usage

### RQ1 — Vulnerability Localization

The dataset for RQ1 is located in `FirmLoc/firmwarePairs/`.

Run the main pipeline:

```bash
python -m vulnagent_cli \
  --old-firmware /path/to/old.bin \
  --new-firmware /path/to/new.bin \
  --cve-id CVE-2024-0000 \
  --workdir /path/to/output
```

**Example:**

```bash
python -m vulnagent_cli \
  --old-firmware /home/ubuntu/R9000-V1.0.4.26.img \
  --new-firmware /home/ubuntu/R9000-V1.0.5.38.img \
  --cve-id CVE-2019-20760 \
  --workdir /home/ubuntu/FirmLoc/RQ1output
```

**Output structure:**

Results are written to a task-scoped directory under `<workdir>/<chat_id>/`:

- `final_report.json` — final summary including status, inputs, artifact paths, and ranking
- `online_search/search_result.json` — processed CVE context retrieved from NVD
- `bindiff/` — dataflow analysis for candidate functions and ranked results

---

### RQ2 — Ablation Study

The dataset for RQ2 is also located in `FirmLoc/firmwarePairs/`.

Set the ablation strategy before running:

```bash
export VULN_ABLATION_STRATEGY="1"   # 1 / 2 / 3 / 4
# Strategy 4 corresponds to the full FirmLoc pipeline
```

Then run the same command as RQ1:

```bash
python -m vulnagent_cli \
  --old-firmware /path/to/old.bin \
  --new-firmware /path/to/new.bin \
  --cve-id CVE-2024-0000 \
  --workdir runs/demo
```

---

### RQ3 — Function Similarity Search (jTrans)

RQ3 reuses the [jTrans](https://github.com/JTrans) framework located at `FirmLoc/RQ3/jTrans`.

#### Install dependencies

```bash
conda install pytorch cudatoolkit=11.0 -c pytorch
python -m pip install simpletransformers networkx pyelftools
```

#### Extract functions from binaries

Place your target binaries in `FirmLoc/RQ3/jTrans/datautils/dataset`, then run:

```bash
cd datautils
python FirmLoc/RQ3/jTrans/datautils/run.py --mode all
```

This produces two `binary_extract.pkl` files under `datautils/extract/`.

#### Compute function similarity

```bash
python FirmLoc/RQ3/jTrans/eval_save.py \
  --retrieval \
  --a_pkl FirmLoc/RQ3/jTrans/datautils/extract/CVE/binaryA_extract.pkl \
  --b_pkl FirmLoc/RQ3/jTrans/datautils/extract/CVE/binaryB_extract.pkl \
  --topk 10
```

- **`binaryA`** is the binary that contains the root-cause vulnerable function as localized by the FirmLoc pipeline (i.e., the source binary from RQ1).
- **`binaryB`** is the target binary under test. The dataset for RQ3 consists of 8 firmware binaries located in `FirmLoc/RQ3/tested_dataset_for_JTrans/`. Run this command once per target binary, substituting the corresponding `.pkl` file for `binaryB`.

This outputs the top-10 most similar functions between `binaryA` and each `binaryB`, indicating where the vulnerability may have propagated in the target firmware.

## Dataset Availability Note
The complete evaluation dataset used in this work exceeds 1 GB in total size and cannot be feasibly hosted on an anonymous repository. It comprises firmware image pairs across multiple vendors and CVE entries, which in their entirety are too large for anonymous submission infrastructure.
To support artifact evaluation, we provide a representative subset that is sufficient to verify the methodology and core claims of the paper. The subset includes some CVE, deliberately selected to cover the two primary vulnerability classes evaluated in our study: injection vulnerabilities, buffer overflow vulnerabilities. This selection ensures that the subset reflects the diversity of both vendor ecosystems and vulnerability types present in the full dataset, and that all major components of the FirmLoc pipeline — CVE context retrieval, binary diffing, dataflow analysis, and function ranking — can be exercised end-to-end on the provided samples.
We confirm that the subset preserves the representativeness and integrity of the evaluation: the included samples span distinct vendors and architectures, and cover each vulnerability category used to measure localization accuracy in the paper. Reviewers can reproduce the key results reported in RQ1 and RQ2 using the firmware pairs provided in FirmLoc/firmwarePairs/, and validate the cross-firmware similarity search in RQ3 using the binaries in FirmLoc/RQ3/tested_dataset_for_JTrans/.