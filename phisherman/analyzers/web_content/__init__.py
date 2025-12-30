"""
Web Content Analysis Module - Modular content analysis for phishing detection.

This module provides specialized analyzers for different aspects of web content:
- SSL/TLS certificate analysis
- HTTP security headers analysis
- JavaScript/meta redirect detection
- User-Agent cloaking detection
- Content scanning for keywords and forms
"""

from phisherman.analyzers.web_content.analyzer import WebContentAnalyzer

__all__ = ["WebContentAnalyzer"]
