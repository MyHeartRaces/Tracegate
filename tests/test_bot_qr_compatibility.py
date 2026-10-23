import json
import subprocess
import sys


def test_issued_connection_qr_still_renders_with_pillow() -> None:
    payloads = [
        "vless://11111111-2222-3333-4444-555555555555@entry.tracegate.test:443?security=reality",
        "hysteria2://legacy-user:legacy-password@endpoint.tracegate.test:443/?obfs=salamander",
        "https://t.me/proxy?server=entry.tracegate.test&port=443&secret=" + "ab" * 40,
    ]
    # Existing bot tests substitute import-time modules. A clean interpreter
    # checks the actual installed qrcode/Pillow pair and the production helper.
    result = subprocess.run(
        [sys.executable, "-c", """
from io import BytesIO
import json
import sys
from PIL import Image
from tracegate.bot.main import _build_qr_png

images = []
for payload in sys.argv[1:]:
    png = _build_qr_png(payload)
    with Image.open(BytesIO(png)) as image:
        assert image.format == 'PNG'
        image.verify()
    with Image.open(BytesIO(png)) as image:
        images.append([image.width, image.height, list(image.getextrema())])
print(json.dumps(images))
""", *payloads],
        check=True, capture_output=True, text=True, timeout=30,
    )
    images = json.loads(result.stdout)
    assert len(images) == len(payloads)
    for width, height, extrema in images:
        assert width == height
        assert width >= 21 * 8
        assert extrema == [0, 255]
