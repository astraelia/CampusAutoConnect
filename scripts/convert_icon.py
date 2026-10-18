"""Convert supplied artwork without redrawing it; remove edge-connected black only."""

import hashlib
import json
import struct
from collections import deque
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QImage

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "校园 Wi‑Fi 萌系连接助手.png"
TARGET = ROOT / "src/campus_autoconnect/assets"
SIZES = (16, 24, 32, 48, 64, 128, 256)


def png_bytes(image: QImage) -> bytes:
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise RuntimeError("PNG encoding failed")
    return bytes(data)


def main() -> None:
    original_bytes = SOURCE.read_bytes()
    source = QImage(str(SOURCE)).convertToFormat(QImage.Format_RGBA8888)
    if source.isNull() or source.width() != source.height():
        raise ValueError("Expected square supplied artwork")
    width, height = source.width(), source.height()
    pixels = bytearray(source.constBits())
    stride = source.bytesPerLine()
    seen = bytearray(width * height)
    queue = deque()

    def enqueue(x: int, y: int) -> None:
        index = y * width + x
        offset = y * stride + 4 * x
        # A low threshold excludes dark colored illustration pixels.
        if not seen[index] and max(pixels[offset : offset + 3]) <= 20:
            seen[index] = 1
            queue.append((x, y))

    for x in range(width):
        enqueue(x, 0)
        enqueue(x, height - 1)
    for y in range(height):
        enqueue(0, y)
        enqueue(width - 1, y)
    while queue:
        x, y = queue.popleft()
        pixels[y * stride + 4 * x + 3] = 0
        for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
            if 0 <= nx < width and 0 <= ny < height:
                enqueue(nx, ny)
    # Remove isolated compression specks outside the rounded illustration as well.
    # The center-connected illustration, including all its dark detail, stays opaque.
    illustration = bytearray(width * height)
    queue.append((width // 2, height // 2))
    illustration[(height // 2) * width + width // 2] = 1
    while queue:
        x, y = queue.popleft()
        for nx, ny in ((x - 1, y), (x + 1, y), (x, y - 1), (x, y + 1)):
            if 0 <= nx < width and 0 <= ny < height:
                index = ny * width + nx
                if not seen[index] and not illustration[index]:
                    illustration[index] = 1
                    queue.append((nx, ny))
    specks = 0
    for y in range(height):
        for x in range(width):
            index = y * width + x
            if not seen[index] and not illustration[index]:
                specks += 1
                seen[index] = 1
                pixels[y * stride + 4 * x + 3] = 0
    output = QImage(pixels, width, height, stride, QImage.Format_RGBA8888).copy()
    original = bytes(source.constBits())
    # All RGB values and every non-background alpha value remain exact.
    assert all(pixels[i] == original[i] for i in range(len(pixels)) if i % 4 != 3)
    assert all(
        pixels[y * stride + x * 4 + 3] == original[y * stride + x * 4 + 3]
        for y in range(height)
        for x in range(width)
        if not seen[y * width + x]
    )
    TARGET.mkdir(parents=True, exist_ok=True)
    clean = png_bytes(output)
    (TARGET / "app.png").write_bytes(clean)
    frames = [
        png_bytes(output.scaled(size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        for size in SIZES
    ]
    offset = 6 + 16 * len(frames)
    entries = []
    for size, frame in zip(SIZES, frames, strict=True):
        entries.append(
            struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(frame), offset)
        )
        offset += len(frame)
    ico = struct.pack("<HHH", 0, 1, len(frames)) + b"".join(entries) + b"".join(frames)
    (TARGET / "app.ico").write_bytes(ico)
    report = {
        "source": SOURCE.name,
        "source_sha256": hashlib.sha256(original_bytes).hexdigest(),
        "size": [width, height],
        "removed_edge_black_pixels": sum(seen) - specks,
        "isolated_outer_speck_pixels": specks,
        "rgb_unchanged_before_scaling": True,
        "non_background_alpha_unchanged": True,
        "ico_sizes": list(SIZES),
        "png_sha256": hashlib.sha256(clean).hexdigest(),
        "ico_sha256": hashlib.sha256(ico).hexdigest(),
    }
    (TARGET / "icon-provenance.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
