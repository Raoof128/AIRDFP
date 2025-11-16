# Contributing to AIRDFP

First off, thank you for considering contributing to the Automated Incident Response & Digital Forensics Platform (AIRDFP)! It's people like you that make AIRDFP such a great tool for the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Testing Guidelines](#testing-guidelines)

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues list as you might find that you don't need to create one. When you are creating a bug report, please include as many details as possible:

**Bug Report Template:**

```markdown
## Description
[Clear description of the bug]

## Steps to Reproduce
1. Go to '...'
2. Click on '...'
3. Execute command '...'
4. See error

## Expected Behavior
[What you expected to happen]

## Actual Behavior
[What actually happened]

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python version: [e.g., 3.11]
- Docker version: [e.g., 24.0.5]
- AIRDFP version: [e.g., 1.0.0]

## Logs
```
[Paste relevant logs here]
```

## Additional Context
[Any other context about the problem]
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a detailed description** of the suggested enhancement
- **Explain why this enhancement would be useful** to most AIRDFP users
- **List any similar features** in other IR platforms

### Contributing Code

We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. If you've changed APIs, update the documentation
4. Ensure the test suite passes
5. Make sure your code follows our coding standards
6. Issue that pull request!

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Docker & Docker Compose
- Git
- Virtual environment tool (venv, virtualenv, or conda)

### Setup Steps

```bash
# 1. Clone your fork
git clone https://github.com/YOUR_USERNAME/AIRDFP.git
cd AIRDFP

# 2. Add upstream remote
git remote add upstream https://github.com/Raoof128/AIRDFP.git

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development dependencies

# 5. Install pre-commit hooks
pre-commit install

# 6. Run validation
python3 tests/validate_system.py

# 7. Run tests
python3 tests/test_core_functionality.py
```

### Development Dependencies

Create `requirements-dev.txt`:
```
# Testing
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-asyncio>=0.21.0

# Code Quality
black>=23.10.0
flake8>=6.1.0
mypy>=1.6.0
pylint>=3.0.0

# Pre-commit
pre-commit>=3.5.0

# Documentation
mkdocs>=1.5.0
mkdocs-material>=9.4.0
```

## Coding Standards

### Python Style Guide

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with the following specifics:

- **Line length**: 100 characters maximum
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Double quotes for strings
- **Imports**: Organized in groups (standard library, third-party, local)

### Code Formatting

We use **Black** for code formatting:

```bash
# Format all Python files
black .

# Check formatting without making changes
black --check .
```

### Type Hints

All functions should include type hints:

```python
def process_alert(alert: Dict[str, Any], severity: int) -> Optional[str]:
    """
    Process a SIEM alert and create a case.

    Args:
        alert: Alert data from SIEM
        severity: Severity level (1-4)

    Returns:
        Case ID if successful, None otherwise
    """
    pass
```

### Documentation

All modules, classes, and functions must have docstrings:

```python
"""
Module for handling evidence collection.

This module provides automated evidence collection using Velociraptor,
supporting multiple collection profiles for different forensic scenarios.
"""

class EvidenceCollector:
    """
    Automated evidence collection orchestrator.

    This class manages evidence collection from endpoints using Velociraptor,
    handling collection profiles, progress tracking, and evidence packaging.

    Attributes:
        server_url: Velociraptor server URL
        api_key: Authentication API key
        evidence_vault: Path to evidence storage
    """

    def collect_evidence(self, hostname: str, profile: str) -> Optional[str]:
        """
        Collect evidence from specified host.

        Args:
            hostname: Target hostname or client ID
            profile: Collection profile name

        Returns:
            Evidence package filename if successful, None otherwise

        Raises:
            ConnectionError: If unable to connect to Velociraptor server
            TimeoutError: If collection exceeds timeout
        """
        pass
```

### Naming Conventions

- **Classes**: `PascalCase` (e.g., `EvidenceCollector`)
- **Functions/Methods**: `snake_case` (e.g., `collect_evidence`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_RETRY_ATTEMPTS`)
- **Private methods**: Prefix with `_` (e.g., `_internal_helper`)

### Error Handling

Always handle errors gracefully:

```python
try:
    result = risky_operation()
except SpecificException as e:
    logger.error(f"Operation failed: {e}")
    return None
except Exception as e:
    logger.critical(f"Unexpected error: {e}")
    raise
```

## Pull Request Process

### 1. Branch Naming

- **Features**: `feature/description` (e.g., `feature/add-aws-forensics`)
- **Bug fixes**: `fix/description` (e.g., `fix/memory-leak-timeline`)
- **Documentation**: `docs/description` (e.g., `docs/update-deployment-guide`)
- **Refactoring**: `refactor/description` (e.g., `refactor/playbook-executor`)

### 2. Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting (no logic changes)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, etc.

**Example:**
```
feat(timeline): Add AWS CloudTrail log parsing

Implement CloudTrail event parsing for timeline analysis,
supporting all AWS service events and multi-region aggregation.

Closes #123
```

### 3. PR Checklist

Before submitting a pull request, ensure:

- [ ] Code follows the style guidelines
- [ ] Self-review of code completed
- [ ] Code is well-commented, especially complex areas
- [ ] Documentation updated (if applicable)
- [ ] Tests added/updated and passing
- [ ] No new warnings generated
- [ ] Validation script passes (`python3 tests/validate_system.py`)
- [ ] CHANGELOG.md updated (for user-facing changes)

### 4. PR Template

```markdown
## Description
[Describe what this PR does]

## Motivation and Context
[Why is this change required? What problem does it solve?]

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update

## How Has This Been Tested?
[Describe the tests you ran and their results]

## Screenshots (if applicable)
[Add screenshots to demonstrate the change]

## Checklist
- [ ] My code follows the code style of this project
- [ ] I have updated the documentation accordingly
- [ ] I have added tests to cover my changes
- [ ] All new and existing tests passed
- [ ] My changes generate no new warnings
```

## Testing Guidelines

### Running Tests

```bash
# Run all tests
python3 tests/test_core_functionality.py

# Run validation
python3 tests/validate_system.py

# Run with coverage (when available)
pytest --cov=. --cov-report=html tests/
```

### Writing Tests

All new features should include tests:

```python
class TestNewFeature(unittest.TestCase):
    """Test new feature functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_data = create_test_data()

    def tearDown(self):
        """Clean up after tests"""
        cleanup_test_data()

    def test_feature_basic(self):
        """Test basic feature functionality"""
        result = new_feature(self.test_data)
        self.assertEqual(result, expected_result)

    def test_feature_edge_case(self):
        """Test edge case handling"""
        result = new_feature(None)
        self.assertIsNone(result)

    def test_feature_error_handling(self):
        """Test error handling"""
        with self.assertRaises(ValueError):
            new_feature(invalid_data)
```

### Test Coverage Goals

- **Minimum coverage**: 80%
- **Target coverage**: 90%
- **Critical paths**: 100%

## Documentation Standards

### Code Comments

- Explain **why**, not **what** (code should be self-explanatory)
- Keep comments up-to-date with code changes
- Use TODO comments for future improvements: `# TODO: Implement retry logic`

### Documentation Files

When updating documentation:
- Use clear, concise language
- Include code examples where applicable
- Keep formatting consistent
- Update table of contents if adding new sections

## Community

### Getting Help

- **GitHub Issues**: For bug reports and feature requests
- **Discussions**: For questions and general discussion
- **Email**: For security issues (security@airdfp.local)

### Recognition

Contributors will be recognized in:
- CHANGELOG.md for significant contributions
- README.md contributors section
- Release notes

## License

By contributing to AIRDFP, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to AIRDFP!** 🎉

Your efforts help make incident response faster and more effective for security teams worldwide.
