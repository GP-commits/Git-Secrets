# Release Notes - Git Secrets Scanner v2.0 (The Turbo Update)

This major release introduces high-performance parallel scanning, a significant reduction in noise, and a refined, professional user interface.

## NEW FEATURES

### Turbo Parallel Scanning
- **5x Faster Scans**: Leverage multi-core performance to scan dozens of repositories in the time it used to take for one.
- **Improved Concurrency**: Control your audit speed with the new `--jobs` or `-j` flag.

### Command Guide
- **Interactive Assistance**: The new `--guide` flag provides a beautifully formatted, categorized overview of every feature, making the tool easier to master for new users.

### Smart Deduplication
- **Intelligent Filtering**: Prevents the same secret from appearing multiple times in the report if it exists in both the current code and history.
- **Priority Labeling**: Automatically prefers specific secret types (e.g., "Google API Key") over generic matches on the same line.

## NOISE REDUCTION

- **History Filtering**: The deep history scan now automatically skips library/vendor folders like `venv`, `node_modules`, and `.dist-info`, ensuring your history reports are 100% actionable.
- **Example Filtering**: Common documentation strings (like `example.com` or `scolvin`) are now automatically filtered out to prevent false positives from third-party libraries.
- **Expanded Skip List**: Added modern defaults like `.vscode`, `.gradle`, and `site-packages` to the automatic exclusion list.

## USER INTERFACE

- **Ultra-Clean Audit Logs**: Removed all emojis and decorative icons in favor of a professional, high-contrast ASCII interface that works perfectly across all terminal types.
- **Improved Reporting**: Clearer summaries of repositories, files, and commits scanned.

## MAINTENANCE

- **Updated Dependencies**: `pytest` has been added to `requirements.txt` to enable professional-grade unit testing for the core scanner logic.
- **Bug Fixes**: Refined the line-number detection and fixed edge cases in clone directory naming.

---
*Thank you for using Git Secrets Scanner! If you find this tool helpful, consider sharing it or contributing to our growing list of secret patterns.*
