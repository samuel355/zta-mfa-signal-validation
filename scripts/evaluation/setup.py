#!/usr/bin/env python3
"""
ZTA Framework Evaluation Setup Script
=====================================

This script sets up the evaluation environment for the multi-source MFA ZTA framework.
It handles dependency installation, database setup, and initial verification.

Usage:
    python setup.py                    # Full setup
    python setup.py --check-only       # Check requirements only
    python setup.py --install-deps     # Install dependencies only
    python setup.py --setup-db         # Setup database only
    python setup.py --verify           # Verify installation
"""

import os
import sys
import subprocess
import argparse
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

import asyncio


class SetupManager:
    """Main setup manager for the evaluation system"""

    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.project_root = self.base_dir.parent.parent
        self.setup_log = []

    def log(self, message: str, level: str = "INFO"):
        """Log setup messages"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        self.setup_log.append(log_entry)

        # Color coding
        colors = {
            "INFO": "\033[94m",    # Blue
            "SUCCESS": "\033[92m", # Green
            "WARNING": "\033[93m", # Yellow
            "ERROR": "\033[91m",   # Red
            "RESET": "\033[0m"     # Reset
        }

        color = colors.get(level, colors["RESET"])
        print(f"{color}{log_entry}{colors['RESET']}")

    def check_python_version(self) -> bool:
        """Check if Python version is compatible"""
        self.log("Checking Python version...")

        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 9):
            self.log(f"Python {version.major}.{version.minor} detected. "
                    "Python 3.9+ is required.", "ERROR")
            return False

        self.log(f"Python {version.major}.{version.minor}.{version.micro} ✅", "SUCCESS")
        return True

    def check_docker(self) -> bool:
        """Check if Docker and Docker Compose are available"""
        self.log("Checking Docker installation...")

        # Check Docker
        try:
            result = subprocess.run(['docker', '--version'],
                                  capture_output=True, text=True, check=True)
            docker_version = result.stdout.strip()
            self.log(f"Docker: {docker_version} ✅", "SUCCESS")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log("Docker not found. Please install Docker.", "ERROR")
            return False

        # Check Docker Compose
        try:
            result = subprocess.run(['docker-compose', '--version'],
                                  capture_output=True, text=True, check=True)
            compose_version = result.stdout.strip()
            self.log(f"Docker Compose: {compose_version} ✅", "SUCCESS")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log("Docker Compose not found. Please install Docker Compose.", "ERROR")
            return False

        return True

    def check_system_resources(self) -> bool:
        """Check if system has adequate resources"""
        self.log("Checking system resources...")

        # Check available memory (simplified check)
        try:
            import psutil
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024**3)

            if available_gb < 2:
                self.log(f"Available memory: {available_gb:.1f}GB. "
                        "Minimum 2GB recommended.", "WARNING")
            else:
                self.log(f"Available memory: {available_gb:.1f}GB ✅", "SUCCESS")

        except ImportError:
            self.log("Cannot check memory (psutil not available). "
                    "Ensure at least 2GB RAM is available.", "WARNING")

        # Check disk space
        try:
            stat = os.statvfs(self.project_root)
            available_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)

            if available_gb < 5:
                self.log(f"Available disk space: {available_gb:.1f}GB. "
                        "Minimum 5GB recommended.", "WARNING")
            else:
                self.log(f"Available disk space: {available_gb:.1f}GB ✅", "SUCCESS")

        except Exception:
            self.log("Cannot check disk space. "
                    "Ensure at least 5GB is available.", "WARNING")

        return True

    def install_dependencies(self) -> bool:
        """Install Python dependencies"""
        self.log("Installing Python dependencies...")

        requirements_file = self.base_dir / "requirements.txt"
        if not requirements_file.exists():
            self.log("requirements.txt not found", "ERROR")
            return False

        try:
            cmd = [sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            self.log("Dependencies installed successfully ✅", "SUCCESS")
            return True

        except subprocess.CalledProcessError as e:
            self.log(f"Failed to install dependencies: {e.stderr}", "ERROR")
            return False

    def check_docker_services(self) -> bool:
        """Check if Docker services are running"""
        self.log("Checking Docker services...")

        compose_file = self.project_root / "compose" / "docker-compose.yml"
        if not compose_file.exists():
            self.log("docker-compose.yml not found", "ERROR")
            return False

        try:
            # Check if services are running
            cmd = ['docker-compose', '-f', str(compose_file), 'ps']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            if "Up" in result.stdout:
                self.log("Some Docker services are running ✅", "SUCCESS")
                return True
            else:
                self.log("No Docker services running. "
                        "Start with: docker-compose up -d", "WARNING")
                return False

        except subprocess.CalledProcessError as e:
            self.log(f"Cannot check Docker services: {e.stderr}", "ERROR")
            return False

    def start_docker_services(self) -> bool:
        """Start Docker services"""
        self.log("Starting Docker services...")

        compose_file = self.project_root / "compose" / "docker-compose.yml"

        try:
            cmd = ['docker-compose', '-f', str(compose_file), 'up', '-d']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            self.log("Docker services started successfully ✅", "SUCCESS")

            # Wait a bit for services to initialize
            self.log("Waiting for services to initialize...")
            time.sleep(30)

            return True

        except subprocess.CalledProcessError as e:
            self.log(f"Failed to start Docker services: {e.stderr}", "ERROR")
            return False

    def setup_database(self) -> bool:
        """Setup database schema"""
        self.log("Setting up database schema...")

        schema_file = self.project_root / "database" / "schema_extension.sql"
        if not schema_file.exists():
            self.log("schema_extension.sql not found", "WARNING")
            return True  # Not critical for basic setup

        # For now, just inform user about manual setup
        # In a production setup, you'd want to automate this
        self.log("Database schema setup requires manual configuration:", "INFO")
        self.log(f"Run: psql -f {schema_file} your_database", "INFO")

        return True

    def verify_installation(self) -> bool:
        """Verify the installation by running basic tests"""
        self.log("Verifying installation...")

        # Check if we can import required packages
        try:
            import httpx
            import pandas as pd
            import numpy as np
            self.log("Core packages importable ✅", "SUCCESS")
        except ImportError as e:
            self.log(f"Import error: {e}", "ERROR")
            return False

        # Try to run a quick evaluation
        try:
            run_script = self.base_dir / "run_evaluation.py"
            if run_script.exists():
                self.log("Testing evaluation runner...")
                cmd = [sys.executable, str(run_script), '--mode', 'quick', '--skip-health-check']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

                if result.returncode == 0:
                    self.log("Evaluation runner test passed ✅", "SUCCESS")
                else:
                    self.log("Evaluation runner test failed", "WARNING")
                    self.log(f"Error: {result.stderr}", "WARNING")
        except Exception as e:
            self.log(f"Cannot test evaluation runner: {e}", "WARNING")

        return True

    def create_env_template(self):
        """Create environment template file"""
        self.log("Creating environment template...")

        env_template = self.project_root / ".env.template"

        template_content = """# ZTA Framework Environment Configuration Template
# Copy this to .env and fill in your values

# Database Configuration
DB_DSN=postgresql://zta_user:your_password@localhost:5432/zta_db
PGOPTIONS=-c search_path=zta,public

# Elasticsearch Configuration
ELASTIC_VERSION=8.10.4
ELASTIC_PASSWORD=your_elastic_password
ELASTIC_PORT=9200
ES_HOST=http://elasticsearch:9200
ES_USER=elastic
ES_PASS=your_elastic_password
ES_API_KEY=your_api_key
ES_INDEX=security-events
ES_MFA_INDEX=mfa-events
ES_VALIDATED_INDEX=validated-context

# Kibana Configuration
KIBANA_PORT=5601
KIBANA_SYSTEM_PASSWORD=your_kibana_password

# Trust Service Configuration
ALLOW_T=0.25
DENY_T=0.70
SIEM_HIGH_BUMP=0.15
SIEM_MED_BUMP=0.07
TRUST_BASE_GAIN=0.05
TRUST_FALLBACK_OBSERVED=0.1

# SIEM Configuration
SEV_HIGH=0.75
SEV_MED=0.25

# Security Configuration
TOTP_SECRET=JBSWY3DPEHPK3PXP

# Simulation Configuration
SIM_MODE=continuous
SIM_SLEEP=0.8
SIM_MAX_ROWS=400
SIM_MAX_PER_FILE=600
SIM_USE_GPS_FROM_WIFI=true
SIM_MIN_WIFI=0.9
SIM_MIN_GPS=0.85
SIM_MIN_TLS=0.7
SIM_MIN_DEVICE=0.85
SIM_PCT_SPOOFING=0.20
SIM_PCT_TLS_TAMPERING=0.15
SIM_PCT_DOS=0.20
SIM_PCT_EXFIL=0.15
SIM_PCT_EOP=0.15
SIM_PCT_REPUDIATION=0.15
SIM_INJECT_GPS_MISMATCH=true
SIM_TLS_BAD_RATE=0.1
SIM_PATCHED_TRUE_RATE=0.8
SIM_GPS_OFFSET_KM=600

# Validation Service Configuration
DIST_THRESHOLD_KM=50
"""

        try:
            with open(env_template, 'w') as f:
                f.write(template_content)
            self.log(f"Environment template created: {env_template} ✅", "SUCCESS")
        except Exception as e:
            self.log(f"Failed to create environment template: {e}", "ERROR")

    def generate_setup_report(self) -> str:
        """Generate setup report"""
        report_file = self.base_dir / "setup_report.md"

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        report_content = f"""# ZTA Framework Setup Report

**Generated**: {timestamp}
**Setup Directory**: {self.base_dir}
**Project Root**: {self.project_root}

## Setup Log
```
"""

        for log_entry in self.setup_log:
            report_content += log_entry + "\n"

        report_content += """```

## Next Steps

### 1. Start Docker Services
```bash
cd """ + str(self.project_root) + """
docker-compose -f compose/docker-compose.yml up -d
```

### 2. Configure Environment
```bash
cp .env.template .env
# Edit .env with your configuration
```

### 3. Setup Database (if needed)
```bash
psql -f database/schema_extension.sql your_database
```

### 4. Run Evaluation
```bash
cd scripts/evaluation
python run_evaluation.py --mode quick
```

## Troubleshooting

- **Docker Issues**: Ensure Docker daemon is running
- **Memory Issues**: Close other applications, minimum 2GB RAM needed
- **Permission Issues**: Ensure user has Docker permissions
- **Network Issues**: Check firewall settings for ports 5432, 9200, 5601

## Support Files Created

- `.env.template` - Environment configuration template
- `setup_report.md` - This report

## Verification Commands

```bash
# Check Docker services
docker-compose -f compose/docker-compose.yml ps

# Check Python packages
python -c "import httpx, pandas, numpy; print('All packages OK')"

# Test evaluation system
python scripts/evaluation/run_evaluation.py --mode quick --skip-health-check
```
"""

        try:
            with open(report_file, 'w') as f:
                f.write(report_content)
            self.log(f"Setup report saved: {report_file} ✅", "SUCCESS")
        except Exception as e:
            self.log(f"Failed to save setup report: {e}", "ERROR")

        return str(report_file)

    def run_full_setup(self) -> bool:
        """Run complete setup process"""
        self.log("Starting ZTA Framework Evaluation Setup", "INFO")
        self.log("=" * 50, "INFO")

        success = True

        # Check requirements
        if not self.check_python_version():
            success = False
        if not self.check_docker():
            success = False

        self.check_system_resources()  # Non-critical

        if not success:
            self.log("Critical requirements not met. Setup cannot continue.", "ERROR")
            return False

        # Install dependencies
        if not self.install_dependencies():
            success = False

        # Create environment template
        self.create_env_template()

        # Setup database (informational)
        self.setup_database()

        # Check/start Docker services
        if not self.check_docker_services():
            self.log("Attempting to start Docker services...", "INFO")
            self.start_docker_services()

        # Verify installation
        self.verify_installation()

        # Generate report
        report_file = self.generate_setup_report()

        self.log("=" * 50, "INFO")
        if success:
            self.log("Setup completed successfully! 🎉", "SUCCESS")
            self.log(f"Setup report: {report_file}", "INFO")
            self.log("", "INFO")
            self.log("Next steps:", "INFO")
            self.log("1. Review and configure .env file", "INFO")
            self.log("2. Start Docker services if not running", "INFO")
            self.log("3. Run: python run_evaluation.py --mode quick", "INFO")
        else:
            self.log("Setup completed with warnings ⚠️", "WARNING")
            self.log("Check the setup report for details", "WARNING")

        return success


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Setup ZTA Framework Evaluation Environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup.py                    # Full setup
  python setup.py --check-only       # Check requirements only
  python setup.py --install-deps     # Install dependencies only
  python setup.py --verify           # Verify installation only
        """
    )

    parser.add_argument(
        '--check-only',
        action='store_true',
        help='Only check system requirements'
    )

    parser.add_argument(
        '--install-deps',
        action='store_true',
        help='Only install Python dependencies'
    )

    parser.add_argument(
        '--setup-db',
        action='store_true',
        help='Only setup database schema'
    )

    parser.add_argument(
        '--verify',
        action='store_true',
        help='Only verify installation'
    )

    parser.add_argument(
        '--start-services',
        action='store_true',
        help='Start Docker services'
    )

    args = parser.parse_args()

    try:
        manager = SetupManager()

        # Handle specific actions
        if args.check_only:
            success = (manager.check_python_version() and
                      manager.check_docker() and
                      manager.check_system_resources())
            return 0 if success else 1

        elif args.install_deps:
            success = manager.install_dependencies()
            return 0 if success else 1

        elif args.setup_db:
            success = manager.setup_database()
            return 0 if success else 1

        elif args.verify:
            success = manager.verify_installation()
            return 0 if success else 1

        elif args.start_services:
            success = manager.start_docker_services()
            return 0 if success else 1

        else:
            # Full setup
            success = manager.run_full_setup()
            return 0 if success else 1

    except KeyboardInterrupt:
        print("\n⏹️  Setup interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
