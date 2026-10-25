"""
Offline QR Code Decoder Input Adapter.
Converts an uploaded QR image into raw decoded text without network calls.
Strictly an input adapter; contains ZERO risk classification or AI logic.
"""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union
import cv2
import numpy as np


@dataclass(frozen=True)
class QRDecodeResult:
    """Structured result of offline QR image decoding."""
    success: bool
    decoded_text: Optional[str]
    error: Optional[str]
    format: str = "QR_CODE"


def _load_image(image_source: Union[str, Path, bytes, np.ndarray]) -> Optional[np.ndarray]:
    """Deterministically loads an image into an OpenCV BGR numpy array."""
    if isinstance(image_source, np.ndarray):
        return image_source

    if isinstance(image_source, bytes):
        nparr = np.frombuffer(image_source, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        return img

    path = Path(image_source)
    if not path.is_file():
        return None

    try:
        with open(path, "rb") as f:
            data = f.read()
        nparr = np.frombuffer(data, np.uint8)
        return cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    except Exception:
        return None


def decode_qr_image(image_source: Union[str, Path, bytes, np.ndarray]) -> QRDecodeResult:
    """
    Decodes a QR code image offline using OpenCV's QRCodeDetector.

    Policy:
    - If no image or corrupted: returns failure.
    - If 0 QR codes found: returns failure ("No valid QR code detected").
    - If multiple QR codes found: rejects ambiguous multi-code images deterministically.
    - If exactly 1 QR code found: returns raw decoded text.
    """
    if image_source is None:
        return QRDecodeResult(
            success=False,
            decoded_text=None,
            error="No image data provided for decoding.",
        )

    img = _load_image(image_source)
    if img is None:
        return QRDecodeResult(
            success=False,
            decoded_text=None,
            error="Could not process image file. Unsupported format or corrupted image.",
        )

    detector = cv2.QRCodeDetector()

    # 1. Multi-code detection to enforce single-code policy
    retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)

    if retval:
        # Filter non-empty detected text strings
        non_empty_codes = [code.strip() for code in decoded_info if code and code.strip()]
        if len(non_empty_codes) > 1:
            return QRDecodeResult(
                success=False,
                decoded_text=None,
                error="Ambiguous image: multiple QR codes detected. Please provide an image with exactly one QR code.",
            )
        elif len(non_empty_codes) == 1:
            return QRDecodeResult(
                success=True,
                decoded_text=non_empty_codes[0],
                error=None,
            )

    # 2. Fallback single-code detection
    single_val, single_pts, _ = detector.detectAndDecode(img)
    if single_val and single_val.strip():
        return QRDecodeResult(
            success=True,
            decoded_text=single_val.strip(),
            error=None,
        )

    return QRDecodeResult(
        success=False,
        decoded_text=None,
        error="No valid QR code detected in the uploaded image.",
    )
