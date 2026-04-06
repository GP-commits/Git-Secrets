<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

<h1 align="center"><img width="1024" height="183" alt="Screenshot_2026-04-06_151021-removebg-preview" src="https://github.com/user-attachments/assets/a31f713e-07ee-4c2a-879f-f8b31c020b7d" />
</h1>

<p align="center">
  <b>A powerful CLI tool that scans GitHub repositories for accidentally committed secrets — API keys, tokens, passwords, private keys, and more.</b>
</p>

<p align="center">
  Like a digital metal detector for your codebase. Find what shouldn't be public before someone else does.
</p>
<p align="center">
  <img src="https://github.com/user-attachments/assets/df168a7a-f5e7-4c2f-8af5-64630b4d4bac" alt="CLI Demo">
</p>



---

## ⚡ Features

- 🔍 **20+ secret patterns** — AWS, GitHub, Google, Stripe, Slack, Discord, Telegram, JWT, SSH keys, database URIs, and more
- 📜 **Full commit history scanning** — detects secrets that were committed and later deleted (default mode)
- 🚀 **Fast mode** — scan only the latest commit for quick audits
- 🔒 **Optional PAT support** — scan private repos or bypass rate limits with a GitHub Personal Access Token
- 🎨 **Colored terminal output** — beautiful, readable reports with redacted snippets
- 📄 **JSON export** — machine-readable output for CI/CD pipelines
- 🧹 **Auto-cleanup** — cloned repos are deleted after scanning
- 🚫 **Fork filtering** — skips forks by default to focus on original code
- 🔁 **CI-friendly** — exits with code `1` when secrets are found

---

## 🏗️ Architecture


<img width="1536" height="1024" alt="GIT secrets scanning flowchart" src="https://github.com/user-attachments/assets/d6b2119c-e608-4e2d-bdda-d1d554acbefc" />


### How it works

1. **Input** — You provide a GitHub username or organization name
2. **Discovery** — The tool queries the GitHub API to fetch all repositories (paginated), filtering out forks
3. **Clone** — Each repository is cloned into a temporary directory (`--depth 1` in fast mode)
4. **Scan** — Two scan passes run:
   - **File scan**: walks the working tree, reads every text file, and matches against 20+ regex patterns
   - **History scan** *(default)*: runs `git log -p --all` to inspect every added line across the full commit history
5. **Deduplicate** — Identical findings from both passes are merged
6. **Report** — A colored terminal report is printed; an optional JSON file is exported
7. **Cleanup** — The temporary clone directory is deleted automatically

---

## 📦 Installation

### Prerequisites

- **Python 3.8+** — [Download Python](https://www.python.org/downloads/)
- **Git** — [Download Git](https://git-scm.com/downloads)

### Setup

```bash
# 1. Clone or download this project
git clone https://github.com/your-username/git-secrets-scanner.git
cd git-secrets-scanner

# 2. (Recommended) Create a virtual environment
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | GitHub API calls |
| `colorama` | Cross-platform colored terminal output |

---

## 🚀 Usage

### Basic scan (full history — recommended)

```bash
python scanner.py <github-username>
```

This clones every non-fork repo and scans both the current files **and the full commit history** for secrets. This is the most thorough mode — it catches secrets that were committed and later deleted.

### Fast mode (latest commit only)

```bash
python scanner.py <github-username> --fast
```

Only scans the current state of files. Much faster, but won't catch deleted secrets.

### With a GitHub Personal Access Token

```bash
python scanner.py <github-username> --token ghp_your_token_here
```

Use a PAT to:
- Scan **private repositories** you own
- Avoid GitHub API **rate limits** (60 requests/hour unauthenticated → 5,000/hour with a token)

> 💡 Generate a PAT at [github.com/settings/tokens](https://github.com/settings/tokens) with `repo` scope for private repos or `public_repo` for public-only access.

### Export results to JSON

```bash
python scanner.py <github-username> --output report.json
```

Produces a structured JSON file for integration with CI/CD pipelines or dashboards.

### Include forked repositories

```bash
python scanner.py <github-username> --include-forks
```

By default, forks are excluded to focus on original code. Use this flag to include them.

### Verbose output

```bash
python scanner.py <github-username> --verbose
```

Shows detailed progress for every file and commit scanned.

### All options combined

```bash
python scanner.py myorg \
  --token ghp_xxxxxxxxxxxx \
  --fast \
  --output report.json \
  --include-forks \
  --verbose
```

### Command-line reference

```
usage: scanner.py [-h] [--token TOKEN] [--fast] [--output OUTPUT]
                  [--include-forks] [--verbose]
                  username

positional arguments:
  username              GitHub username or organization name

options:
  -h, --help            show this help message and exit
  --token, -t TOKEN     GitHub Personal Access Token (optional)
  --fast, -f            Fast mode: scan only the latest commit (skip history)
  --output, -o OUTPUT   Export results as JSON to this file path
  --include-forks       Include forked repositories (excluded by default)
  --verbose, -v         Show detailed progress output
```

---

## 🔍 Detected Secret Types

| Category | Secret Type | Example Pattern |
|----------|------------|-----------------|
| **AWS** | Access Key ID | `AKIA...` (20 chars) |
| **AWS** | Secret Access Key | `aws_secret_access_key = ...` |
| **GitHub** | Personal Access Token (classic) | `ghp_...` |
| **GitHub** | Fine-grained PAT | `github_pat_...` |
| **GitHub** | OAuth Access Token | `gho_...` |
| **Google** | API Key | `AIza...` (39 chars) |
| **Google** | OAuth Client Secret | `client_secret = ...` |
| **Stripe** | Secret Key | `sk_live_...` |
| **Stripe** | Publishable Key | `pk_live_...` |
| **Slack** | Bot Token | `xoxb-...-...-...` |
| **Slack** | Webhook URL | `https://hooks.slack.com/services/...` |
| **Discord** | Bot Token | `M...` / `N...` (base64 format) |
| **Telegram** | Bot Token | `123456789:ABC-DEF...` |
| **SendGrid** | API Key | `SG....` |
| **Mailgun** | API Key | `key-...` (32 hex chars) |
| **Twilio** | API Key | `SK...` (32 hex chars) |
| **Heroku** | API Key | `heroku_api_key = ...` (UUID) |
| **NPM** | Access Token | `npm_...` |
| **Azure** | Storage Account Key | `AccountKey = ...` (88 chars) |
| **Firebase** | Cloud Messaging Key | `AAAA...:...` |
| **Auth** | JSON Web Token (JWT) | `eyJ...eyJ...` |
| **Auth** | Private Key (RSA/DSA/EC/SSH) | `-----BEGIN ... PRIVATE KEY-----` |
| **Database** | Connection String | `mongodb://...`, `postgres://...` |
| **Generic** | Password/Secret assignments | `password = "..."`, `api_key = "..."` |

---

## 📊 Sample Output

```
   ██████╗ ██╗████████╗    ███████╗███████╗ ██████╗██████╗ ███████╗████████╗███████╗
  ██╔════╝ ██║╚══██╔══╝    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝
  ██║  ███╗██║   ██║       ███████╗█████╗  ██║     ██████╔╝█████╗     ██║   ███████╗
  ██║   ██║██║   ██║       ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   ╚════██║
  ╚██████╔╝██║   ██║       ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ███████║
   ╚═════╝ ╚═╝   ╚═╝       ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝

  [*] Fetching repositories for @your-username …
  [✓] Found 12 repositories (forks excluded).
  [*] [1/12] Cloning my-project …
  [SECRET]   2 potential secret(s) in current files

  ════════════════════════════════════════════════════════════════════════
    SCAN REPORT — @your-username
  ════════════════════════════════════════════════════════════════════════

    Repositories scanned : 12
    Files scanned        : 347
    Commits scanned      : 1203
    Duration             : 42.3s

    🔑 2 potential secret(s) found!

    ┌─ my-project (2 finding(s))
    ├── AWS Access Key ID
    │   config/settings.py:L14 [file]
    │   AKIAIO********************
    │
    └── Generic Secret Assignment
        .env.example:L3 [file]
        DB_PASSWORD="sup3r_********************
```

### JSON export structure

```json
{
  "username": "your-username",
  "repos_scanned": 12,
  "files_scanned": 347,
  "commits_scanned": 1203,
  "scan_duration_seconds": 42.3,
  "total_findings": 2,
  "findings": [
    {
      "repo": "my-project",
      "file": "config/settings.py",
      "line_number": 14,
      "secret_type": "AWS Access Key ID",
      "snippet": "AKIAIO********************",
      "source": "file"
    }
  ],
  "errors": []
}
```

---

## 🔧 Configuration

### Tunable constants in `scanner.py`

| Constant | Default | Description |
|----------|---------|-------------|
| `MAX_FILE_SIZE` | 2 MB | Skip files larger than this |
| `REPOS_PER_PAGE` | 100 | GitHub API pagination size |
| `BINARY_EXTENSIONS` | 40+ types | File extensions to skip |
| `SKIP_DIRS` | `.git`, `node_modules`, etc. | Directories to completely ignore |

### Adding custom secret patterns

Add new patterns to the `SECRET_PATTERNS` list in `scanner.py`:

```python
SECRET_PATTERNS.append((
    "My Custom Token",
    re.compile(r"\b(myapp_[A-Za-z0-9]{32})\b")
))
```

---

## 🔄 CI/CD Integration

The scanner returns **exit code 1** when secrets are found, making it easy to integrate into CI pipelines:

### GitHub Actions example

```yaml
name: Secret Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install requests colorama
      - run: python scanner.py ${{ github.repository_owner }} --fast --output report.json
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: secret-scan-report
          path: report.json
```

---

## ⚠️ Legal & Ethical Notice

> **This tool must only be used on repositories you own or have explicit permission to audit.**
>
> Scanning other people's repositories for secrets without authorization is **illegal and unethical**. This tool is intended for self-auditing and security hygiene only.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-pattern`)
3. Add your changes
4. Test against your own repos
5. Submit a pull request

### Ideas for contributions

- Add more secret patterns (Cloudflare, DigitalOcean, etc.)
- `.gitsecretsignore` file for suppressing false positives
- Webhook notifications (Slack, Discord, email)
- Pre-commit hook integration
- HTML report generation

---

## 📝 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ❤️ for developers who care about security.
</p>
