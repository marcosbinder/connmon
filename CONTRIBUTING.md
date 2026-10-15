# Contributing to connmon

Thank you for your interest in contributing to **connmon**! We welcome bug fixes, documentation improvements, and thoughtful feature additions.

---

## Core Philosophy: Zero Mandatory Dependencies

The guiding architectural principle of `connmon` is:
> **Zero mandatory external dependencies.** The core monitoring daemon, database layer, web dashboard, PDF generator, and cryptographic timestamping MUST run using only the **Python Standard Library** and built-in **SQLite**.

Any pull request that introduces a mandatory third-party package for the base runtime will not be accepted. Optional integrations or dev tools (e.g. `pytest`, `ruff`, optional fallback tools) are welcome as long as the runtime degrades gracefully if they are absent.

---

## Local Development Workflow

### 1. Clone the repository
```bash
git clone https://github.com/marcosbinder/connmon.git
cd connmon
```

### 2. Set up a virtual environment (optional)
```bash
python3 -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate
```

### 3. Install development tooling
```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### 4. Code style & Linting
We use [Ruff](https://github.com/astral-sh/ruff) for fast, clean linting:
```bash
ruff check .
```
To automatically fix safe formatting issues:
```bash
ruff check --fix .
```

### 5. Running the Test Suite
Run the test suite using `pytest`:
```bash
python -m pytest -v
```

All tests should pass before submitting a pull request.

---

## Pull Request Guidelines

1. **Create a topic branch**: `git checkout -b feature/my-new-feature` or `fix/my-bugfix`.
2. **Keep changes focused**: One logical change per PR is easier to review.
3. **Include tests**: Add unit tests in `tests/` covering your changes or edge cases.
4. **Preserve backward compatibility**: Ensure database migrations and CLI arguments remain compatible with existing installations.
5. **Update documentation**: If introducing new flags or endpoints, update both `README.md` (English) and `README.pt-BR.md` (Portuguese).
