"""Dessine l'icône de l'application, sans dépendance : assets/icon.ico et assets/icon64.rgba."""
import math
import pathlib
import struct
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent / "assets"
SAMPLES = 4


def segment_distance(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def color_at(x, y):
    """Coordonnées de 0 à 1. Renvoie (r, g, b, a) entre 0 et 1."""
    radius = 0.22
    qx = max(abs(x - 0.5) - (0.5 - radius), 0)
    qy = max(abs(y - 0.5) - (0.5 - radius), 0)
    if math.hypot(qx, qy) > radius:
        return (0, 0, 0, 0)
    tint = (x + y) / 2
    background = (0.31 - 0.10 * tint, 0.27 - 0.06 * tint, 0.90 - 0.15 * tint, 1)

    dist = math.hypot(x - 0.5, y - 0.5)
    ring = any(abs(dist - r) < 0.021 for r in (0.16, 0.25, 0.34))
    if ring and not (y > 0.60 and dist > 0.1):
        background = (0.62, 0.60, 0.97, 1)

    stroke = min(
        segment_distance(x, y, 0.33, 0.52, 0.46, 0.65),
        segment_distance(x, y, 0.46, 0.65, 0.70, 0.37),
    )
    if stroke < 0.055:
        return (1, 1, 1, 1)
    return background


def render(size):
    rows = bytearray()
    for j in range(size):
        for i in range(size):
            total = [0.0, 0.0, 0.0, 0.0]
            for sj in range(SAMPLES):
                for si in range(SAMPLES):
                    r, g, b, a = color_at((i + (si + 0.5) / SAMPLES) / size, (j + (sj + 0.5) / SAMPLES) / size)
                    total[0] += r * a
                    total[1] += g * a
                    total[2] += b * a
                    total[3] += a
            alpha = total[3] / SAMPLES**2
            scale = 1 / total[3] if total[3] else 0
            rows += bytes(round(255 * min(1, c * scale)) for c in total[:3]) + bytes([round(255 * alpha)])
    return bytes(rows)


def png(rgba, size):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    raw = b"".join(b"\0" + rgba[y * size * 4 : (y + 1) * size * 4] for y in range(size))
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main():
    ROOT.mkdir(exist_ok=True)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [png(render(s), s) for s in sizes]
    directory = struct.pack("<HHH", 0, 1, len(sizes))
    offset = 6 + 16 * len(sizes)
    for size, image in zip(sizes, images):
        byte = 0 if size == 256 else size
        directory += struct.pack("<BBBBHHII", byte, byte, 0, 0, 1, 32, len(image), offset)
        offset += len(image)
    (ROOT / "icon.ico").write_bytes(directory + b"".join(images))
    (ROOT / "icon64.rgba").write_bytes(render(64))


main()
