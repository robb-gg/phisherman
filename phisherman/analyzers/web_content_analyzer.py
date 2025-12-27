"""
Web Content Analyzer - Backwards compatibility module.

DEPRECATED: This module has been refactored into phisherman/analyzers/web_content/
Please import from phisherman.analyzers.web_content instead.

This file is kept for backwards compatibility and will be removed in a future version.
"""

import warnings

# Issue deprecation warning
warnings.warn(
    "Importing from phisherman.analyzers.web_content_analyzer is deprecated. "
    "Use phisherman.analyzers.web_content instead.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export from new location for backwards compatibility
from phisherman.analyzers.web_content import WebContentAnalyzer

__all__ = ["WebContentAnalyzer"]
