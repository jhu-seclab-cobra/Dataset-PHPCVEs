# Dataset PHPCVEs

A curated dataset containing 258 PHP web application vulnerabilities from 2007 to 2025, focusing on the five most prevalent taint-style vulnerabilities from CVEListV5. The dataset includes 145 XSS vulnerabilities (56.2%), 75 SQL injection vulnerabilities (29.1%), and 38 other critical vulnerabilities (14.7%) such as unrestricted file upload, code injection, and command injection.

## Quick Start

### Option 1: Download Pre-built Dataset
The easiest way to get started is to download the pre-built dataset from our [release page](https://github.com/YichaoXu/Dataset-PHPCVEs/releases).

### Option 2: Build Dataset from Source
If you want to build the dataset yourself or customize the collection process:

1. Clone the repository:
```bash
git clone URL
cd Dataset-PHPCVEs
```

2. Set up the environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Build the dataset:
```bash
python reproduce.py download \
    --project-types "Web App" \
    --cwe-types "79,89,434,94,77" \
    .cache/collected.csv \
    ./CVEs
```

The dataset will be organized as `CVEs/CWE-ID/CVE-ID/`.

## Dataset Information

### Vulnerability Types
The dataset includes five major types of vulnerabilities:

| CWE Type | Description | Count | Percentage |
|----------|-------------|-------|------------|
| CWE-79   | Cross-site Scripting (XSS) | 145 | 56.2% |
| CWE-89   | SQL Injection | 75 | 29.1% |
| CWE-434  | Unrestricted File Upload | 15 | 5.8% |
| CWE-94   | Code Injection | 13 | 5.0% |
| CWE-77   | Command Injection | 10 | 3.9% |

### Collection Criteria
The dataset is built using the following filtering criteria:
1. CVE records must contain PHP-related keywords
2. Must include GitHub patch links in the references
3. Patches must contain at least one related PHP file.
4. Repository must be classified as a Web Application. 

### Dataset Statistics
- Total CVEs: 258
- Year Range: 2007 - 2025
- Project Types: Web Applications
- Unique CWE Types: 5

## Usage Notes
- The dataset is organized by CWE type and CVE ID for easy navigation
- Each CVE entry contains the original vulnerable code and its patch
- The dataset is static as of February 14, 2025
- For consistency, we recommend using the pre-built dataset from the release page

## Citation
If you use this dataset in your research, please cite our paper.

## Contact
For questions or issues, please open an issue or contact the project maintainer.
