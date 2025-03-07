# Environment Setup

This document provides instructions for setting up your development environment for OpenWISP Radius.

## Installation

*Installation instructions would go here*

## Configuration

*Configuration instructions would go here*

## Troubleshooting

### Resolving the TypeError: unhashable type: list on Windows

Windows users running Python 3.9.0 may encounter a `TypeError: unhashable type: list` error when running tests. This error occurs due to compatibility issues with type annotations in some XML processing libraries used by the test suite.

There are two ways to resolve this issue:

#### Option 1: Upgrade Python (Recommended)

Upgrading to Python 3.9.2 or later is the recommended solution:

1. Download the latest Python version from the [official Python website](https://www.python.org/downloads/)
2. Install the new Python version
3. Create a new virtual environment:

```bash
# Create a new virtual environment with the upgraded Python
python -m venv new_venv

# Activate the new environment
# On Windows Command Prompt:
new_venv\Scripts\activate
# On Windows PowerShell:
.\new_venv\Scripts\Activate.ps1

# Install requirements
pip install -e .[dev]
```

#### Option 2: Pin Dependency Versions

If upgrading Python is not possible, you can pin the problematic dependencies:

1. Clear pip cache:

```bash
pip cache purge
```

2. Install specific versions of the problematic packages:

```bash
pip install elementpath==2.5.0 xmlschema==2.0.0

# Reinstall project dependencies
pip install -e .[dev]
```

After applying either solution, run the tests again to verify the issue is resolved.

### Troubleshooting Cryptography on Windows

Windows users may encounter DLL load errors related to the cryptography package (e.g., "ImportError: DLL load failed while importing _rust"). Try these solutions:

1. Update pip and cryptography:
   ```bash
   pip install --upgrade pip cryptography
   ```

2. Install Rust if needed:
   - Visit https://www.rust-lang.org/tools/install and follow the installation instructions

3. Try a specific version of cryptography:
   ```bash
   pip install cryptography==41.0.7
   ```

4. If issues persist, consider using pre-compiled wheels:
   ```bash
   pip install --only-binary=cryptography cryptography
   ```