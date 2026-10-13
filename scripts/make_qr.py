"""Generate docs/judge_qr.png pointing at /judge. Usage: python scripts/make_qr.py [BASE_URL]

Needs ``pip install "qrcode[pil]"`` (dev-only; not a runtime dependency).
The URL carries no credentials or tokens, by design.
"""

import sys
from pathlib import Path

import qrcode
from qrcode.constants import ERROR_CORRECT_M

base = (sys.argv[1] if len(sys.argv) > 1 else "https://agentwarden.onrender.com").rstrip("/")
url = f"{base}/judge"
img = qrcode.QRCode(error_correction=ERROR_CORRECT_M, box_size=16, border=4)
img.add_data(url)
img.make(fit=True)
out = Path(__file__).resolve().parent.parent / "docs" / "judge_qr.png"
img.make_image(fill_color="black", back_color="white").save(out)
print(f"wrote {out} -> {url}")
