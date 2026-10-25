"""
Offline QR code decoding package.
Serves strictly as an input adapter; contains zero risk analysis logic.
"""
from core.qr.decoder import QRDecodeResult, decode_qr_image

__all__ = ["QRDecodeResult", "decode_qr_image"]
