"""
Application orchestration layer.
Provides unified entry points for end-to-end URL and QR risk analysis.
"""
from core.application.analyze import AnalysisReport, analyze_url, analyze_qr_image

__all__ = ["AnalysisReport", "analyze_url", "analyze_qr_image"]
