"""
Flask Web Application for Explainable URL & Link Risk Screening.
Strictly a presentation layer: consumes AnalysisReport from core.application.
Contains ZERO AI or inference logic.
"""
import sys
from pathlib import Path

# Ensure project root is in sys.path when executed directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, render_template, request

from core.application.analyze import analyze_url, analyze_qr_image


def create_app() -> Flask:
    """Application factory for the Flask web presentation server."""
    base_dir = Path(__file__).resolve().parent

    app = Flask(
        __name__,
        template_folder=str(base_dir / "templates"),
        static_folder=str(base_dir / "static"),
    )

    @app.route("/", methods=["GET"])
    def index():
        """Renders the main technical dashboard."""
        return render_template("index.html")

    @app.route("/presentation", methods=["GET"])
    def presentation():
        """Renders the 12-slide Viva Presentation deck."""
        return render_template("presentation.html")

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        """
        API endpoint that accepts a URL and returns a structured AnalysisReport.
        Accepts application/json or application/x-www-form-urlencoded.
        """
        raw_url = ""
        if request.is_json:
            data = request.get_json(silent=True) or {}
            raw_url = data.get("url", "")
        else:
            raw_url = request.form.get("url", "")

        try:
            report = analyze_url(raw_url)
            return jsonify(report.to_dict()), 200
        except Exception as e:
            # Clean technical error response without exposing raw internal tracebacks
            return jsonify({
                "raw_url": raw_url,
                "is_valid": False,
                "error": f"Analysis encountered a processing error: {str(e)}",
                "verdict": "REVIEW",
                "highest_severity": "NONE",
                "triggered_patterns": [],
                "triggered_rules": [],
                "risk_factors": ["Processing exception occurred during analysis."],
                "explanation": "The request could not be processed due to an internal validation fault.",
                "safe_disclaimer": None,
                "proof_tree_text": "(Analysis aborted)",
                "proof_tree_nodes": [],
                "astar_evidence": None,
            }), 400

    @app.route("/api/analyze-qr", methods=["POST"])
    def api_analyze_qr():
        """
        API endpoint that accepts an uploaded QR image, decodes it offline,
        and analyzes the resulting URL using the existing pipeline.
        """
        if "qr_image" not in request.files:
            return jsonify({
                "success": False,
                "error": "No QR image file was uploaded. Please select an image file.",
                "decoded_text": None,
                "report": None,
            }), 400

        file = request.files["qr_image"]
        if not file.filename:
            return jsonify({
                "success": False,
                "error": "No file selected. Please select a valid QR image.",
                "decoded_text": None,
                "report": None,
            }), 400

        try:
            file_bytes = file.read()
            if not file_bytes:
                return jsonify({
                    "success": False,
                    "error": "Uploaded file is empty.",
                    "decoded_text": None,
                    "report": None,
                }), 400

            decoded, report = analyze_qr_image(file_bytes)

            if not decoded.success:
                return jsonify({
                    "success": False,
                    "error": decoded.error,
                    "decoded_text": None,
                    "report": None,
                }), 400

            if decoded.error:
                # Decoded successfully, but content is not an analyzable URL (e.g. plain text)
                return jsonify({
                    "success": True,
                    "error": decoded.error,
                    "decoded_text": decoded.decoded_text,
                    "report": None,
                }), 200

            return jsonify({
                "success": True,
                "error": None,
                "decoded_text": decoded.decoded_text,
                "report": report.to_dict() if report else None,
            }), 200

        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"QR processing encountered an error: {str(e)}",
                "decoded_text": None,
                "report": None,
            }), 400

    return app


if __name__ == "__main__":
    app = create_app()
    print("Starting Explainable URL Risk Screening Dashboard on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
