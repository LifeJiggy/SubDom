# Contributing to Bug Bounty Beast

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `python test_runtime.py`
6. Commit your changes
7. Push to your fork and submit a Pull Request

## Development Setup

```bash
git clone https://github.com/YOUR-USERNAME/SubDom.git
cd Subdom
pip install -r requirements.txt
python test_runtime.py  # Verify everything works
```

## Project Structure

```
Subdom/
├── Subdom.py              # Main tool (all-in-one)
├── test_runtime.py        # Runtime error test suite
├── requirements.txt       # Python dependencies
├── subdomains.txt         # Subdomain wordlist
├── directories.txt        # Directory wordlist (auto-downloaded)
├── subdom_config.yaml     # Generated config file
├── plugins/               # Custom scan plugins
├── bug_bounty_output/     # Scan results
├── WAF__BYPASS_HEADER.json # WAF headers reference
└── images/                # Screenshots
```

## How to Contribute

### Bug Reports

- Open an issue with a clear title
- Include Python version and OS
- Provide steps to reproduce
- Include error output (run with `--verbose`)

### Feature Requests

- Open an issue with `[Feature]` prefix
- Explain the use case
- Describe expected behavior

### Code Contributions

#### Adding a New Passive Source

1. Create a function following this pattern:

```python
def run_yoursource_enum(target: str, verbose: bool) -> Set[str]:
    """Enumerate subdomains via YourSource."""
    subdomains = set()
    # Your implementation here
    return subdomains
```

2. Add it to `subdomain_enumeration_passive()` tools list
3. Add rate limiting via `RATE_LIMITER.wait("yoursource")`

#### Adding a New Security Test

1. Create a function following this pattern:

```python
def test_your_vuln(url: str, proxies: List[str] = None, verbose: bool = False) -> Dict[str, Any]:
    """Test for your vulnerability."""
    result = {"url": url, "vulnerable": False}
    # Your implementation here
    return result
```

2. Add CLI flag in `main()`
3. Add execution block in the main scan flow

#### Adding a New Cloud Provider

1. Add naming patterns to `enumerate_cloud_storage()`
2. Add `check_url()` calls for each service
3. Include progress tracking

### Coding Standards

- **Single file**: All code lives in `Subdom.py` (keep it that way)
- **No external dependencies**: Use `requests` + stdlib only (except optional playwright/pyyaml)
- **Graceful degradation**: If a library isn't installed, skip that feature
- **Thread safety**: Use locks for shared state
- **Deduplication**: Always check before adding to result sets
- **Rate limiting**: Use `RATE_LIMITER.wait(service)` before external requests
- **Error handling**: Catch exceptions, log them, continue scanning
- **ANSI colors**: Use the `C` class for all terminal output

### Testing

Run the test suite before submitting:

```bash
python test_runtime.py
```

All 25 tests must pass. Add new tests for new features.

### Pull Request Guidelines

- Keep PRs focused (one feature/fix per PR)
- Include a clear description
- Reference any related issues
- Make sure `test_runtime.py` passes
- Don't break existing features

## Architecture Decisions

- **Single file**: Easier to distribute and maintain
- **No compilation**: Pure Python, runs anywhere
- **Graceful degradation**: Features degrade when dependencies are missing
- **Config over code**: Use YAML config for scan presets
- **Dedup everything**: Content fingerprinting prevents false positives
- **Atomic writes**: Prevent corrupt output files

## Code of Conduct

- Be respectful
- Focus on authorized security testing
- Don't submit malicious code
- Help others learn

## Questions?

Open an issue with `[Question]` prefix.
