# AIRDFP Scripts

This directory contains utility and demonstration scripts for AIRDFP.

## Quick Start Script

**`quick_start.sh`** - Automated deployment and setup

Performs a complete AIRDFP setup including:
- Dependency validation (Python, Docker, Docker Compose)
- Python virtual environment creation
- Dependency installation
- Docker service deployment
- System validation

### Usage

```bash
./scripts/quick_start.sh
```

### What It Does

1. **Dependency Check**: Validates Python 3, Docker, and Docker Compose
2. **Environment Setup**: Creates and activates Python virtual environment
3. **Install Dependencies**: Installs all required Python packages
4. **Docker Services**: Starts TheHive, Cortex, and Elasticsearch
5. **Health Checks**: Validates all services are running
6. **System Validation**: Runs comprehensive system checks

### Requirements

- Python 3.8+
- Docker 20.10+
- Docker Compose 1.29+
- 8 GB RAM minimum
- 20 GB free disk space

---

## Demo Script

**`demo_incident.py`** - Interactive ransomware incident demonstration

Simulates a complete incident response workflow:
- SIEM alert ingestion
- Automated case creation
- Evidence collection
- Memory forensics analysis
- Timeline generation with ML anomaly detection
- Automated report generation

### Usage

```bash
python3 scripts/demo_incident.py
```

### What It Demonstrates

1. **SIEM Integration**: Alert ingestion with ML severity classification
2. **Case Management**: Automated TheHive case creation
3. **Evidence Collection**: Velociraptor orchestration (simulated)
4. **Memory Forensics**: Volatility 3 analysis with IOC extraction
5. **Timeline Analysis**: Super timeline with anomaly detection
6. **MITRE ATT&CK**: TTP mapping and attack narrative
7. **Reporting**: Executive and technical report generation
8. **Chain of Custody**: Evidence integrity verification

### Output

The demo provides:
- Visual progress through 7 incident response steps
- Simulated analysis results
- IOC extraction examples
- Attack timeline reconstruction
- MITRE ATT&CK mapping
- Performance metrics (99.6% MTTR improvement)

### Duration

Approximately 2-3 minutes

---

## Additional Scripts

### Development Scripts

See the `Makefile` in the root directory for additional utility commands:

```bash
make help              # Show all available commands
make quick-start       # Automated quick start (uses quick_start.sh)
make install           # Install production dependencies
make install-dev       # Install development dependencies
make test              # Run test suite
make validate          # Run system validation
make lint              # Run code linting
make format            # Format code with black
make security-scan     # Run security scans
make docker-up         # Start Docker services
make docker-down       # Stop Docker services
make docker-logs       # View service logs
make clean             # Clean generated files
```

---

## Troubleshooting

### Quick Start Issues

**Services not starting:**
```bash
# Check Docker daemon
docker info

# Check port conflicts
netstat -tuln | grep -E '9000|9001|9200'

# Check logs
docker-compose logs -f
```

**Elasticsearch not ready:**
```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# Increase wait time if needed (edit quick_start.sh)
# Change: sleep 60
# To: sleep 90
```

**Python environment errors:**
```bash
# Remove and recreate virtual environment
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Demo Script Issues

**Import errors:**
```bash
# Ensure you're in the AIRDFP root directory
cd /path/to/AIRDFP
python3 scripts/demo_incident.py
```

**No color output:**
```bash
# If terminal doesn't support colors, output will still work
# Colors are automatically handled by the script
```

---

## Creating Custom Scripts

When creating new scripts for this directory:

1. **Make executable**: `chmod +x scripts/your_script.sh`
2. **Add shebang**: `#!/bin/bash` or `#!/usr/bin/env python3`
3. **Document**: Add entry to this README
4. **Test**: Verify on clean system
5. **Error handling**: Use `set -e` for bash scripts

### Script Template (Bash)

```bash
#!/bin/bash
set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Your script logic here
echo -e "${GREEN}Success${NC}"
```

### Script Template (Python)

```python
#!/usr/bin/env python3
"""
Script description
"""

import sys

def main():
    try:
        # Your logic here
        print("Success")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on contributing new scripts.

---

**Questions?** Check the [FAQ](../docs/FAQ.md) or [open an issue](https://github.com/Raoof128/AIRDFP/issues).
