#!/usr/bin/env python3
"""
scanner.py - grep your github repos for leaked secrets

python scanner.py <username> [--token TOKEN] [--fast] [--output FILE] [--verbose]
"""

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

# windows terminal chokes on unicode without this
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        sys.stdout = io.TextIOWrapper(
            sys.stdout.buffer, encoding="utf-8", errors="replace"
        )
        sys.stderr = io.TextIOWrapper(
            sys.stderr.buffer, encoding="utf-8", errors="replace"
        )

try:
    import requests
except ImportError:
    print("[!] 'requests' is required. Install it with: pip install requests")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    # no colors, no problem
    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = Style = _NoColor()




GITHUB_API = "https://api.github.com"
REPOS_PER_PAGE = 100

BINARY_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".flac", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar", ".xz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".obj",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pyc", ".pyo", ".class", ".jar",
    ".db", ".sqlite", ".sqlite3",
    ".DS_Store",
})

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB cap

SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "vendor", "dist", "build", ".tox", ".mypy_cache",
})


SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key ID",
     re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])")),
    ("AWS Secret Access Key",
     re.compile(r"""(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""")),

    ("GitHub Personal Access Token (classic)",
     re.compile(r"\b(ghp_[A-Za-z0-9]{36,})\b")),
    ("GitHub Fine-grained PAT",
     re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,})\b")),
    ("GitHub OAuth Access Token",
     re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b")),

    ("Google API Key",
     re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("Google OAuth Client Secret",
     re.compile(r"""(?i)client[_\-]?secret[\s]*[=:]\s*['"]?([A-Za-z0-9\-_]{24,})['"]?""")),

    ("Slack Bot Token",
     re.compile(r"\b(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})\b")),
    ("Slack Webhook URL",
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)")),

    ("Stripe Secret Key",
     re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b")),
    ("Stripe Publishable Key",
     re.compile(r"\b(pk_live_[0-9a-zA-Z]{24,})\b")),

    ("Twilio API Key",
     re.compile(r"\b(SK[0-9a-fA-F]{32})\b")),

    ("SendGrid API Key",
     re.compile(r"\b(SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,})\b")),

    ("Mailgun API Key",
     re.compile(r"\b(key-[0-9a-zA-Z]{32})\b")),

    ("JSON Web Token",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),

    ("RSA/DSA/EC/OpenSSH Private Key",
     re.compile(r"-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")),

    ("Heroku API Key",
     re.compile(r"""(?i)heroku[_\-]?api[_\-]?key[\s]*[=:]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?""")),

    ("Database Connection String",
     re.compile(r"""(?i)(mongodb(\+srv)?|mysql|postgres(ql)?|redis|amqp)://[^\s'"]{10,}""")),

    ("Generic Secret Assignment",
     re.compile(r"""(?i)(password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|credentials|private[_\-]?key)\s*[=:]\s*['"]([^'"]{8,})['"]""")),

    ("Discord Bot Token",
     re.compile(r"\b([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,})\b")),

    ("Telegram Bot Token",
     re.compile(r"\b(\d{8,10}:[A-Za-z0-9_-]{32})\b")),

    ("NPM Access Token",
     re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),

    ("Azure Storage Account Key",
     re.compile(r"""(?i)(?:AccountKey|storage[_\-]?key)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{88})['"]?""")),

    ("Firebase Cloud Messaging Key",
     re.compile(r"\b(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,})\b")),
]




@dataclass
class Finding:
    repo: str
    file: str
    line_number: int
    secret_type: str
    snippet: str
    source: str  # where we found it: "file" or "history"
    raw_snippet: str = ""

@dataclass
class ScanResult:
    username: str
    repos_scanned: int = 0
    files_scanned: int = 0
    commits_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_duration_seconds: float = 0.0




def _log(msg: str, level: str = "info", verbose_only: bool = False):
    """Fancy print."""
    if verbose_only and not _VERBOSE:
        return
    prefix_map = {
        "info":    f"{Fore.CYAN}[*]{Style.RESET_ALL}",
        "success": f"{Fore.GREEN}[✓]{Style.RESET_ALL}",
        "warn":    f"{Fore.YELLOW}[!]{Style.RESET_ALL}",
        "error":   f"{Fore.RED}[✗]{Style.RESET_ALL}",
        "finding": f"{Fore.RED}{Style.BRIGHT}[SECRET]{Style.RESET_ALL}",
    }
    print(f"  {prefix_map.get(level, '[?]')} {msg}")

_VERBOSE = False
_SHOW_SECRETS = False


def _redact(s: str, keep: int = 6) -> str:
    if len(s) <= keep:
        return s
    return s[:keep] + "*" * (len(s) - keep)


def _is_text_file(filepath: Path) -> bool:
    """Quick check — skip binaries and huge files."""
    if filepath.suffix.lower() in BINARY_EXTENSIONS:
        return False
    try:
        if filepath.stat().st_size > MAX_FILE_SIZE:
            return False
        if filepath.stat().st_size == 0:
            return False
    except OSError:
        return False
    return True




def fetch_repos(username: str, token: Optional[str] = None,
                include_forks: bool = False) -> list[dict]:
    """Hit the github api, grab all repos. Paginates automatically. Tries /users first, falls back to /orgs."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    repos: list[dict] = []
    page = 1

    while True:
        url = f"{GITHUB_API}/users/{username}/repos"
        params = {"per_page": REPOS_PER_PAGE, "page": page, "type": "all"}
        resp = requests.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code == 404:
            # not a user? try as org
            url = f"{GITHUB_API}/orgs/{username}/repos"
            resp = requests.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code == 403:
            # hit the rate limit wall
            reset = resp.headers.get("X-RateLimit-Reset")
            if reset:
                wait = max(int(reset) - int(time.time()), 0) + 1
                _log(f"Rate-limited. Resets in {wait}s. Provide a --token to avoid this.", "warn")
            else:
                _log("Rate-limited by GitHub API. Provide a --token.", "warn")
            break

        if resp.status_code != 200:
            _log(f"GitHub API returned {resp.status_code}: {resp.text[:200]}", "error")
            break

        batch = resp.json()
        if not batch:
            break

        for r in batch:
            if r.get("fork") and not include_forks:
                continue
            repos.append(r)

        page += 1

    return repos




def clone_repo(clone_url: str, dest: Path, fast: bool = False) -> bool:
    """git clone wrapper. --depth 1 when fast mode is on."""
    cmd = ["git", "clone", "--quiet"]
    if fast:
        cmd += ["--depth", "1"]
    cmd += [clone_url, str(dest)]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=300)
        return True
    except subprocess.CalledProcessError as exc:
        _log(f"Clone failed: {exc.stderr.decode(errors='replace')[:200]}", "error")
        return False
    except subprocess.TimeoutExpired:
        _log(f"Clone timed out for {clone_url}", "error")
        return False




def scan_file_content(content: str, repo_name: str, filepath: str,
                      source: str = "file") -> list[Finding]:
    """Throw every regex at each line and collect hits."""
    findings: list[Finding] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        # skip minified junk
        if len(line) > 2000:
            continue
        for secret_type, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                snippet = line.strip()
                if len(snippet) > 160:
                    snippet = snippet[:160] + "…"
                findings.append(Finding(
                    repo=repo_name,
                    file=filepath,
                    line_number=line_num,
                    secret_type=secret_type,
                    snippet=_redact(snippet, keep=40),
                    source=source,
                    raw_snippet=snippet,
                ))
    return findings


def scan_latest_files(repo_dir: Path, repo_name: str) -> tuple[list[Finding], int]:
    """Walk the repo on disk and check every readable file."""
    findings: list[Finding] = []
    files_scanned = 0

    for root, dirs, files in os.walk(repo_dir):
        # prune junk dirs in-place so os.walk skips them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            fpath = Path(root) / fname
            if not _is_text_file(fpath):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                continue

            rel = str(fpath.relative_to(repo_dir)).replace("\\", "/")
            results = scan_file_content(content, repo_name, rel, source="file")
            findings.extend(results)
            files_scanned += 1

    return findings, files_scanned


def scan_commit_history(repo_dir: Path, repo_name: str) -> tuple[list[Finding], int]:
    """Parse `git log -p --all` output and check every added line for secrets."""
    findings: list[Finding] = []
    commits_scanned = 0

    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--all", "--diff-filter=A",
             "--no-color", "--format=commit %H"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=600,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        _log(f"History scan timed out for {repo_name}", "warn")
        return findings, commits_scanned
    except Exception as exc:
        _log(f"History scan error for {repo_name}: {exc}", "error")
        return findings, commits_scanned

    current_file = ""
    for line in proc.stdout.splitlines():
        if line.startswith("commit "):
            commits_scanned += 1
            continue
        if line.startswith("diff --git"):
            parts = line.split(" b/")
            current_file = parts[-1] if len(parts) > 1 else ""
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added_line = line[1:]
            if len(added_line) > 2000:
                continue
            for secret_type, pattern in SECRET_PATTERNS:
                if pattern.search(added_line):
                    snippet = added_line.strip()
                    if len(snippet) > 160:
                        snippet = snippet[:160] + "…"
                    findings.append(Finding(
                        repo=repo_name,
                        file=current_file,
                        line_number=0,  # can't get a real line number from diffs
                        secret_type=secret_type,
                        snippet=_redact(snippet, keep=40),
                        source="history",
                        raw_snippet=snippet,
                    ))

    return findings, commits_scanned




def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Same secret showing up in file scan AND history scan? keep one."""
    seen: set[tuple] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.repo, f.file, f.secret_type, f.snippet)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique




def print_banner():
    banner = rf"""
{Fore.RED}{Style.BRIGHT}
   ██████╗ ██╗████████╗    ███████╗███████╗ ██████╗██████╗ ███████╗████████╗███████╗
  ██╔════╝ ██║╚══██╔══╝    ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝
  ██║  ███╗██║   ██║       ███████╗█████╗  ██║     ██████╔╝█████╗     ██║   ███████╗
  ██║   ██║██║   ██║       ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   ╚════██║
  ╚██████╔╝██║   ██║       ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ███████║
   ╚═════╝ ╚═╝   ╚═╝       ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝
{Style.RESET_ALL}
  {Fore.YELLOW}╔══════════════════════════════════════════════════════════════════════════╗
  ║  GitHub Repository Secrets Scanner                                       ║
  ║  ⚠  Use ONLY on repositories you own or have permission to audit.        ║
  ╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_report(result: ScanResult):
    """Dump the results to terminal in a readable format."""
    print()
    print(f"  {Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}  SCAN REPORT — @{result.username}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{'═' * 72}{Style.RESET_ALL}")
    print()
    print(f"  {Fore.WHITE}  Repositories scanned : {Style.BRIGHT}{result.repos_scanned}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Files scanned        : {Style.BRIGHT}{result.files_scanned}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Commits scanned      : {Style.BRIGHT}{result.commits_scanned}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}  Duration             : {Style.BRIGHT}{result.scan_duration_seconds:.1f}s{Style.RESET_ALL}")
    print()

    if not result.findings:
        print(f"  {Fore.GREEN}{Style.BRIGHT}  ✅ No secrets detected. Your repos look clean!{Style.RESET_ALL}")
        print()
        return

    # group findings by repo name for readability
    by_repo: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_repo.setdefault(f.repo, []).append(f)

    total = len(result.findings)
    color = Fore.RED if total > 0 else Fore.GREEN
    print(f"  {color}{Style.BRIGHT}  🔑 {total} potential secret(s) found!{Style.RESET_ALL}")
    print()

    for repo, findings in by_repo.items():
        print(f"  {Fore.MAGENTA}{Style.BRIGHT}  ┌─ {repo} ({len(findings)} finding(s)){Style.RESET_ALL}")
        for i, f in enumerate(findings):
            is_last = (i == len(findings) - 1)
            branch = "└" if is_last else "├"
            src_tag = f"{Fore.BLUE}[history]{Style.RESET_ALL}" if f.source == "history" else f"{Fore.CYAN}[file]{Style.RESET_ALL}"
            line_info = f"L{f.line_number}" if f.line_number else "diff"

            print(f"  {Fore.MAGENTA}  {branch}── {Fore.YELLOW}{f.secret_type}{Style.RESET_ALL}")
            print(f"  {Fore.MAGENTA}  {'   ' if is_last else '│  '} "
                  f"{Fore.WHITE}{f.file}:{line_info} {src_tag}{Style.RESET_ALL}")
            
            output_snippet = f.raw_snippet if _SHOW_SECRETS else f.snippet
            print(f"  {Fore.MAGENTA}  {'   ' if is_last else '│  '} "
                  f"{Fore.RED}{output_snippet}{Style.RESET_ALL}")
            print()

    if result.errors:
        print(f"  {Fore.YELLOW}  ⚠ {len(result.errors)} error(s) during scan:{Style.RESET_ALL}")
        for e in result.errors:
            print(f"  {Fore.YELLOW}    • {e}{Style.RESET_ALL}")
        print()


def export_json(result: ScanResult, filepath: str):
    """Write everything to a json file."""
    data = {
        "username": result.username,
        "repos_scanned": result.repos_scanned,
        "files_scanned": result.files_scanned,
        "commits_scanned": result.commits_scanned,
        "scan_duration_seconds": result.scan_duration_seconds,
        "total_findings": len(result.findings),
        "findings": [{k: v for k, v in asdict(f).items() if k != "raw_snippet"} for f in result.findings],
        "errors": result.errors,
    }
    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    _log(f"Report exported to {filepath}", "success")




def main():
    global _VERBOSE, _SHOW_SECRETS

    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for accidentally committed secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py octocat
  python scanner.py octocat --token ghp_xxxx --output report.json
  python scanner.py my-org --fast --verbose
        """,
    )
    parser.add_argument("username", help="GitHub username or organization name")
    parser.add_argument("--token", "-t", help="GitHub Personal Access Token (optional)")
    parser.add_argument("--fast", "-f", action="store_true",
                        help="Fast mode: scan only the latest commit (skip history)")
    parser.add_argument("--output", "-o",
                        help="Export results as JSON to this file path")
    parser.add_argument("--include-forks", action="store_true",
                        help="Include forked repositories (excluded by default)")
    parser.add_argument("--unsafe-show-secrets", action="store_true",
                        help="Show the full unredacted secrets in the output")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Bypass interactive confirmation for --unsafe-show-secrets")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed progress output")
    args = parser.parse_args()
    _VERBOSE = args.verbose
    _SHOW_SECRETS = args.unsafe_show_secrets

    if _SHOW_SECRETS:
        if os.environ.get("CI", "").lower() == "true":
            _log("CI environment detected. Ignoring --unsafe-show-secrets and reverting to redaction.", "warn")
            _SHOW_SECRETS = False
        elif not sys.stdout.isatty() and not args.yes:
            _log("Non-interactive terminal detected without --yes. Assuming unsafe. Reverting to redaction.", "warn")
            _SHOW_SECRETS = False
        elif not args.yes:
            prompt = input("  [!] WARNING: You are exposing full secrets. Do not use in shared or CI environments.\n  Type 'yes' to proceed: ")
            if prompt.strip().lower() != 'yes':
                _log("Aborted exposing secrets. Reverting to redaction.", "warn")
                _SHOW_SECRETS = False
                
    if _SHOW_SECRETS:
        print(f"  {Fore.RED}{Style.BRIGHT}[WARNING] You are exposing full secrets. Do not use in shared or CI environments.{Style.RESET_ALL}")

    print_banner()

    # grab the repo list from github
    _log(f"Fetching repositories for {Fore.WHITE}{Style.BRIGHT}@{args.username}{Style.RESET_ALL} …")
    repos = fetch_repos(args.username, token=args.token, include_forks=args.include_forks)

    if not repos:
        _log("No repositories found. Check the username/org or provide a --token.", "warn")
        sys.exit(0)

    _log(f"Found {Fore.WHITE}{Style.BRIGHT}{len(repos)}{Style.RESET_ALL} "
         f"{'repository' if len(repos) == 1 else 'repositories'} "
         f"(forks {'included' if args.include_forks else 'excluded'}).", "success")

    result = ScanResult(username=args.username)
    start_time = time.time()

    # clone everything into a tmp folder, scan it, then nuke the folder
    tmp_root = Path(tempfile.mkdtemp(prefix="gitsecrets_"))
    _log(f"Working directory: {tmp_root}", verbose_only=True)

    try:
        for idx, repo in enumerate(repos, start=1):
            name = repo["name"]
            clone_url = repo.get("clone_url") or repo.get("html_url")
            _log(f"[{idx}/{len(repos)}] Cloning {Fore.WHITE}{Style.BRIGHT}{name}{Style.RESET_ALL} …")

            dest = tmp_root / name
            if not clone_repo(clone_url, dest, fast=args.fast):
                result.errors.append(f"Failed to clone {name}")
                continue

            result.repos_scanned += 1

            # check current files on disk
            _log(f"  Scanning files in {name} …", verbose_only=True)
            file_findings, n_files = scan_latest_files(dest, name)
            result.files_scanned += n_files
            result.findings.extend(file_findings)

            if file_findings:
                _log(f"  {len(file_findings)} potential secret(s) in current files", "finding")

            # dig through old commits too (skip if --fast)
            if not args.fast:
                _log(f"  Scanning commit history for {name} …", verbose_only=True)
                hist_findings, n_commits = scan_commit_history(dest, name)
                result.commits_scanned += n_commits
                result.findings.extend(hist_findings)

                if hist_findings:
                    _log(f"  {len(hist_findings)} potential secret(s) in commit history", "finding")

            _log(f"  Done with {name}.", "success", verbose_only=True)

    except KeyboardInterrupt:
        _log("Scan interrupted by user.", "warn")
    finally:
        # always clean up, even if we ctrl+c'd
        _log("Cleaning up temporary files …", verbose_only=True)
        shutil.rmtree(tmp_root, ignore_errors=True)

    result.scan_duration_seconds = time.time() - start_time

    # squash dupes
    result.findings = deduplicate(result.findings)

    # print results
    print_report(result)

    if args.output:
        export_json(result, args.output)

    # non-zero exit = secrets found (handy for CI pipelines)
    sys.exit(1 if result.findings else 0)


if __name__ == "__main__":
    main()
