"""
Explanation and Proof Tree package.
Reconstructs logical reasoning traces and produces explainable proof trees.
"""
from core.explanation.proof_tree import (
    ProofNode,
    ExplanationResult,
    build_proof_tree,
    build_explanation,
    render_proof_tree,
)

__all__ = [
    "ProofNode",
    "ExplanationResult",
    "build_proof_tree",
    "build_explanation",
    "render_proof_tree",
]
