# Contributing to Git Secrets Scanner

First off, thank you for considering contributing to Git Secrets Scanner! It's people like you that make open source tools better and more secure for everyone.

This document describes how to contribute, what standard of code we expect, and how to get your changes merged.

## 🤝 How Can I Contribute?

### Reporting Bugs
If you find a bug, please create an issue on GitHub. Include:
- A clear, descriptive title.
- Steps to reproduce the problem.
- Expected versus actual behavior.
- Any relevant logs or output.

### Suggesting Enhancements
Have an idea for a new feature? We'd love to hear it! Some ideas from our roadmap include:
- Adding more secret patterns (Cloudflare, DigitalOcean, etc.)
- A `.gitsecretsignore` file for suppressing false positives
- Webhook notifications (Slack, Discord, email)
- Pre-commit hook integration
- HTML report generation

### Submitting Pull Requests
1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Commit your changes**: `git commit -m 'Add some feature'`
4. **Push to the branch**: `git push origin feature/your-feature-name`
5. **Open a Pull Request** against the main branch.

## 🔧 Development Setup

1. **Clone your fork**:
   ```bash
   git clone https://github.com/your-username/Git-Secrets.git
   cd Git-Secrets
   ```

2. **Create a virtual environment (recommended)**:
   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🔍 Adding Custom Secret Patterns

One of the most valuable contributions is adding new patterns to detect more secrets.

To add a new pattern, edit `scanner.py` and append to the `SECRET_PATTERNS` list. Use compiled regexes for performance:

```python
import re

SECRET_PATTERNS.append((
    "My Custom Token",
    re.compile(r"\b(myapp_[A-Za-z0-9]{32})\b")
))
```

Please make sure to test your new regex patterns against both positive and negative examples before submitting!

## ✅ Testing Your Changes

Before submitting your PR, please:
- Test your changes manually by running the scanner against your own test repositories.
- Ensure the script still works perfectly with `--fast` mode, full history mode, and JSON output formatting.
- Check that no new dependencies are added unless absolutely necessary and discussed first.

## ⚠️ Legal & Ethical Notice

When testing your changes, **you must only use the tool on repositories you own or have explicit permission to audit.** Scanning other people's repositories for secrets without authorization is illegal and unethical.

Thank you again for your contribution!
