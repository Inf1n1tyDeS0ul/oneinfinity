# Contributing to One&Infinity

First off, thank you for considering contributing to One&Infinity! We welcome bug reports, feature requests, and pull requests.

## Development Setup
1. Clone the repository
2. Set up the Python virtual environment: `python3 -m venv .venv && source .venv/bin/activate`
3. Install dependencies: `pip install -r requirements.txt`
4. Set up environment variables based on `.env.example`
5. Run tests locally before submitting a PR.

## Coding Standards
* Write clean, type-hinted Python code.
* Ensure no secrets, personal data, or client data is ever checked in.
* Write concise docstrings and document new features in `README.md` and `ARCHITECTURE.md`.
* Follow the existing architecture layout.

## Pull Requests
* Open an issue first to discuss major changes.
* Link the issue in your PR.
* Provide clear testing instructions and verify no regressions were introduced.