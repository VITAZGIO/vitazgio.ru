"""Package the existing Android/PWA VG artwork as a Windows multi-size icon."""
from pathlib import Path
from PIL import Image

root = Path(__file__).resolve().parents[2]
out = root / "desktop" / "assets"
out.mkdir(exist_ok=True)
icon = Image.open(root / "static" / "icons" / "maskable-512.png").convert("RGBA")
icon.save(out / "icon.png")
icon.save(out / "icon.ico", sizes=[(n, n) for n in (16, 24, 32, 48, 64, 128, 256)])
