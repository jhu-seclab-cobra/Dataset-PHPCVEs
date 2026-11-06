# PHPCVEs

> PHP + [CVE](https://www.cve.org/) (Common Vulnerabilities and Exposures): CVE records whose fix is a commit in a PHP web application on GitHub.

258 taint-style CVEs in PHP web applications, each with the source code of its vulnerable commit.

## Install

```bash
git clone https://github.com/jhu-seclab-cobra/Dataset-PHPCVEs.git
```

The clone is about 2.4 GB: the compressed source archives of all 258 datapoints.

## Usage

Extract the source code of the datapoints you need (Python 3.12 or later, no third-party packages):

```bash
python tools/extract.py                    # every CVE
python tools/extract.py --cwe 79 --cwe 89  # CVEs labeled CWE-79 or CWE-89
python tools/extract.py CVE-2010-10010     # one CVE
```

Each archive is checked against the sha256 values in its `meta.json` and extracted to `cves/<CVE>/codes/`, which Git ignores. An existing `codes/` is kept unless `--force` is given.

## Dataset

258 CVEs (CVE-2007-* to CVE-2025-*) in 130 GitHub repositories, labeled with five taint-style CWEs:

| CWE | Weakness | CVEs |
|---|---|---|
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Cross-site Scripting | 145 |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | SQL Injection | 75 |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted Upload of File with Dangerous Type | 15 |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Code Injection | 13 |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Command Injection | 10 |

How the CVEs were selected: [docs/collection.md](docs/collection.md).

## Format

```
cves.csv                          one row per datapoint
cves/<CVE>/meta.json              datapoint metadata
cves/<CVE>/source/source.tar.xz   source archive (cut into source.tar.xz.000, .001, ... above 48 MiB)
cves/<CVE>/codes/                 extracted source (created by tools/extract.py)
```

`cves.csv` columns: `cve_id`, `cwe_ids`, `github_repo`, `commit`, `fix_commit`, `project_type`.

`meta.json` fields:

| Field | Meaning |
|---|---|
| `cve_id` | CVE identifier |
| `cwe_ids` | CWE labels of the CVE record |
| `github_repo`, `github_url` | Repository the CVE record's fix commit belongs to |
| `commit` | Vulnerable commit: the first parent of `fix_commit`; the archive holds its tree |
| `fix_commit` | Commit the CVE record links as the fix |
| `project_type` | Repository type (`Web App` for every datapoint) |
| `snapshot_origin` | Where the commit was fetched from: `github_url`, or another repository holding the same commit when the original is no longer available |
| `source_package` | Archive size and sha256, each part's path, size and sha256, and the command, Git and xz versions that produced the archive |

```json
{
  "cve_id": "CVE-2010-10010",
  "cwe_ids": ["CWE-79"],
  "github_repo": "StarsAlliance/PsychoStats",
  "github_url": "https://github.com/StarsAlliance/PsychoStats",
  "commit": "fa17054b742815a6f80f791b02b0256aec8fbe6c",
  "fix_commit": "5d3b7311fd5085ec6ea1b1bfa9a05285964e07e4",
  "project_type": "Web App",
  "snapshot_origin": "https://github.com/StarsAlliance/PsychoStats",
  "source_package": {
    "archive_size": 13129388,
    "archive_sha256": "21d4b551c0d3f27a4df652bae11d07534f5deac6c1d993ad6abdbc1a694ad87f",
    "parts": [
      {
        "path": "source/source.tar.xz",
        "size": 13129388,
        "sha256": "21d4b551c0d3f27a4df652bae11d07534f5deac6c1d993ad6abdbc1a694ad87f"
      }
    ],
    "generation_command": "...",
    "git_version": "git version 2.50.1 (Apple Git-155)",
    "xz_version": "xz (XZ Utils) 5.8.4"
  }
}
```

## Citation

```bibtex
@inproceedings{xu_cobra_2026,
  title = {{CoBrA}: Context-, Branch-sensitive Static Analysis for Detecting Taint-style Vulnerabilities in {PHP} Web Applications},
  author = {Xu, Yichao and Kang, Mingqing and Thimmaiah, Neil and Gjomemo, Rigel and Venkatakrishnan, V. N. and Cao, Yinzhi},
  booktitle = {Proceedings of the IEEE/ACM 48th International Conference on Software Engineering (ICSE)},
  publisher = {ACM},
  pages = {1943--1954},
  year = {2026},
  doi = {10.1145/3744916.3773195}
}
```

## License

[MIT](LICENSE). The archived source code keeps the license of its own repository.
