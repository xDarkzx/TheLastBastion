"""
Forensic sub-analyzer package.

Each module contains a single-responsibility analyzer that implements
the BaseAnalyzer interface. The ForensicIntegrityAnalyzer composes
these modules via dependency injection.
"""
from core.verification.analyzers.base import BaseAnalyzer

__all__ = ["BaseAnalyzer"]
