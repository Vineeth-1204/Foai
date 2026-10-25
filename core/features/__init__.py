"""
Feature and Fact Generation Package.
Converts ParsedURL objects into positive propositional facts and structured evidence.
"""
from core.features.fact_generator import FeatureResult, extract_features

__all__ = ["FeatureResult", "extract_features"]
