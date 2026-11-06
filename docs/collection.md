# How PHPCVEs Was Collected

This page records how the 258 datapoints in `cves.csv` were selected. The selection is fixed: using the dataset needs only `cves.csv` and `cves/`, not a rerun of the collection.

The collection tool (`reproduce.py` and `src/`) is kept at tag [`v2025.03`](https://github.com/jhu-seclab-cobra/Dataset-PHPCVEs/tree/v2025.03). Rerunning it does not reproduce the dataset exactly, because the project-type classifier reads live GitHub data and several project types were corrected by hand (step 5).

## Source

All CVE records of [CVEListV5](https://github.com/CVEProject/cvelistV5) release `cve_2025-02-14_1700Z` (`2025-02-14_all_CVEs_at_midnight.zip`).

## Steps

1. **PHP-related CVE.** The record's description or affected product names contain one of: `php`, `wordpress`, `drupal`, `laravel`, `symfony`, `composer`, `phpunit`, `magento`, `cakephp`, `codeigniter`, `zend`, `moodle` (case-insensitive substring match).
2. **GitHub fix commit.** A reference of the record links a GitHub commit (`https://github.com/<owner>/<repo>/commit/<40-hex sha>`). That commit is the datapoint's `fix_commit`.
3. **PHP change.** The fix commit modifies at least one file ending in `.php`, `.phtml`, `.php3`, `.php4`, `.php5`, `.phps` or `.inc`.
4. **Vulnerable snapshot.** The first parent of the fix commit is the datapoint's `commit`; its source tree is the archived snapshot.
5. **Project type.** The repository's GitHub description and the first 200 characters of its README are classified by [`repo_classifier`](https://pypi.org/project/repo-classifier/) 0.1.3 into `Web App`, `Framework`, `Framework Plugin`, `Framework Theme`, `Library`, `CLI App` or `Unknown`. The types of PrestaShop, revive-adserver and some other repositories were then corrected by hand.

Steps 1–5 yield 865 CVEs.

6. **Selection.** Keep the CVEs whose project type is `Web App` and whose CWE is one of the five taint-style weaknesses below. This leaves 258 CVEs from 130 repositories.

| CWE | Weakness | CVEs |
|---|---|---|
| [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Cross-site Scripting | 145 |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | SQL Injection | 75 |
| [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | Unrestricted Upload of File with Dangerous Type | 15 |
| [CWE-94](https://cwe.mitre.org/data/definitions/94.html) | Code Injection | 13 |
| [CWE-77](https://cwe.mitre.org/data/definitions/77.html) | Command Injection | 10 |

## Snapshot Archives

Each `cves/<CVE>/source/` holds `git archive --format=tar <commit> | xz -T1 -6`, cut into 48 MiB parts when larger: exactly the files of the commit's tree, including any macOS metadata files (`.DS_Store`, `__MACOSX/`) the repository itself committed. The exact command, Git and xz versions, and the sha256 of the archive and of every part are in the datapoint's `meta.json` under `source_package`.

The commit is fetched from `github_url`. When that repository is no longer available, it is fetched from another repository holding the same commit, recorded as `snapshot_origin`; since a commit id is the hash of its content, the tree is the same.

Every extracted archive was compared file by file with the snapshots the `v2025.03` collection tool had extracted from GitHub zip archives of the same commits. File contents are identical for all 258 datapoints. The remaining differences are defects of those older snapshots, not of the archives:

- **Non-ASCII file names** (16 datapoints): the zip extraction decoded UTF-8 names as CP437, so `Français.php` became `Fran├ºais.php`. The archives keep the original UTF-8 names.
- **Symbolic links** (17 datapoints): the zip extraction stored each symbolic link as a regular file. The archives keep them as symbolic links.
- **Local files** (CVE-2024-29859): three `.DS_Store` files that the old snapshot gained on disk and the commit does not contain.
