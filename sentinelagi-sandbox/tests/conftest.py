"""
Pytest configuration and shared fixtures.
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Set test environment
os.environ.setdefault("ENVIRONMENT", "testing")
os.environ.setdefault("LOG_LEVEL", "DEBUG")
os.environ.setdefault("SANDBOX_RUNTIME", "runc")  # Use default runtime for tests
os.environ.setdefault("REDIS_HOST", "localhost")
os.environ.setdefault("SECURITY_SECRET_KEY", "test-secret-key")
