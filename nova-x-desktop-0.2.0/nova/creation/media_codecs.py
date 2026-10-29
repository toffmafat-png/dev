"""Deterministic local codecs, procedural generators, 3D mesh validators, document builders, and §132 format converters.

Uses Python's standard library (`zlib`, `struct`, `wave`, `zipfile`, `xml`, `csv`,
`sqlite3`) as a zero-bloat baseline and automatically delegates to installed host
tools (`convert`/ImageMagick, `ffmpeg`, `openscad`, `pandoc`, `soffice`) when
available while truthfully recording which tool produced each output.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import shutil
import sqlite3
import struct
import subprocess
import wave
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path
from typing import Any

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# Compact 5x7 ASCII bitmap font for pure-Python SVG/chart label fallback rendering.
_FONT_5X7: dict[str, tuple[int, ...]] = {
    " ": (0, 0, 0, 0, 0, 0, 0),
    "-": (0, 0, 0, 31, 0, 0, 0),
    ".": (0, 0, 0, 0, 0, 12, 12),
    ":": (0, 12, 12, 0, 12, 12, 0),
    "/": (1, 2, 4, 8, 16, 0, 0),
    "0": (14, 17, 19, 21, 25, 17, 14),
    "1": (4, 12, 4, 4, 4, 4, 14),
    "2": (14, 17, 1, 6, 8, 16, 31),
    "3": (31, 2, 4, 6, 1, 17, 14),
    "4": (2, 6, 10, 18, 31, 2, 2),
    "5": (31, 16, 30, 1, 1, 17, 14),
    "6": (6, 8, 16, 30, 17, 17, 14),
    "7": (31, 1, 2, 4, 8, 8, 8),
    "8": (14, 17, 17, 14, 17, 17, 14),
    "9": (14, 17, 17, 15, 1, 2, 12),
    "A": (14, 17, 17, 31, 17, 17, 17),
    "B": (30, 17, 17, 30, 17, 17, 30),
    "C": (14, 17, 16, 16, 16, 17, 14),
    "D": (28, 18, 17, 17, 17, 18, 28),
    "E": (31, 16, 16, 30, 16, 16, 31),
    "F": (31, 16, 16, 30, 16, 16, 16),
    "G": (14, 17, 16, 23, 17, 17, 15),
    "H": (17, 17, 17, 31, 17, 17, 17),
    "I": (14, 4, 4, 4, 4, 4, 14),
    "J": (7, 2, 2, 2, 2, 18, 12),
    "K": (17, 18, 20, 24, 20, 18, 17),
    "L": (16, 16, 16, 16, 16, 16, 31),
    "M": (17, 27, 21, 21, 17, 17, 17),
    "N": (17, 25, 21, 19, 17, 17, 17),
    "O": (14, 17, 17, 17, 17, 17, 14),
    "P": (30, 17, 17, 30, 16, 16, 16),
    "Q": (14, 17, 17, 17, 21, 18, 13),
    "R": (30, 17, 17, 30, 20, 18, 17),
    "S": (15, 16, 16, 14, 1, 1, 30),
    "T": (31, 4, 4, 4, 4, 4, 4),
    "U": (17, 17, 17, 17, 17, 17, 14),
    "V": (17, 17, 17, 17, 17, 10, 4),
    "W": (17, 17, 17, 21, 21, 27, 17),
    "X": (17, 17, 10, 4, 10, 17, 17),
    "Y": (17, 17, 10, 4, 4, 4, 4),
    "Z": (31, 1, 2, 4, 8, 16, 31),
}


# ------------------------------------------------------------ PNG & Raster Studio


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)


def write_rgba_png(path: Path, width: int, height: int, rgba_bytes: bytes | bytearray) -> Path:
    """Write a spec-compliant 8-bit RGBA PNG image using stdlib `zlib` and `struct`."""
    if width <= 0 or height <= 0:
        raise ValueError("PNG width and height must be positive.")
    expected = width * height * 4
    if len(rgba_bytes) != expected:
        raise ValueError(f"Expected {expected} RGBA bytes, got {len(rgba_bytes)}.")
    stride = width * 4
    scanlines = bytearray()
    mv = memoryview(rgba_bytes)
    for y in range(height):
        scanlines.append(0)  # Filter type 0 (None)
        scanlines.extend(mv[y * stride : (y + 1) * stride])
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    compressed = zlib.compress(bytes(scanlines), level=6)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(PNG_SIGNATURE + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", compressed) + _png_chunk(b"IEND", b""))
    return out


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def read_rgba_png(path: Path) -> tuple[int, int, bytearray]:
    """Decode an 8-bit RGB or RGBA PNG into a flat RGBA bytearray."""
    raw = Path(path).read_bytes()
    if not raw.startswith(PNG_SIGNATURE):
        raise ValueError("Not a valid PNG signature.")
    pos = 8
    width = height = bit_depth = color_type = 0
    idat_parts: list[bytes] = []
    while pos + 8 <= len(raw):
        length = struct.unpack(">I", raw[pos : pos + 4])[0]
        ctype = raw[pos + 4 : pos + 8]
        chunk_data = raw[pos + 8 : pos + 8 + length]
        expected_crc = struct.unpack(">I", raw[pos + 8 + length : pos + 12 + length])[0]
        actual_crc = zlib.crc32(ctype + chunk_data) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"PNG chunk {ctype!r} failed CRC check.")
        pos += 12 + length
        if ctype == b"IHDR":
            width, height, bit_depth, color_type, _comp, _flt, interlace = struct.unpack(">IIBBBBB", chunk_data)
            if interlace != 0 or bit_depth != 8 or color_type not in {2, 6}:
                convert_bin = shutil.which("convert")
                if convert_bin:
                    tmp_ppm = Path(path).with_suffix(".decode_tmp.ppm")
                    try:
                        subprocess.run([convert_bin, str(path), f"PPM:{tmp_ppm}"], check=True, timeout=8, capture_output=True)
                        return read_ppm_as_rgba(tmp_ppm)
                    finally:
                        tmp_ppm.unlink(missing_ok=True)
                raise ValueError(f"Unsupported PNG mode bit_depth={bit_depth} color_type={color_type} interlace={interlace}")
        elif ctype == b"IDAT":
            idat_parts.append(chunk_data)
        elif ctype == b"IEND":
            break

    bpp = 4 if color_type == 6 else 3
    stride = width * bpp
    decompressed = zlib.decompress(b"".join(idat_parts))
    recon = bytearray(height * stride)
    src = 0
    for y in range(height):
        ftype = decompressed[src]
        src += 1
        row_out = y * stride
        prev_row = (y - 1) * stride
        for x in range(stride):
            val = decompressed[src + x]
            left = recon[row_out + x - bpp] if x >= bpp else 0
            up = recon[prev_row + x] if y > 0 else 0
            up_left = recon[prev_row + x - bpp] if (y > 0 and x >= bpp) else 0
            if ftype == 0:
                out_v = val
            elif ftype == 1:
                out_v = (val + left) & 0xFF
            elif ftype == 2:
                out_v = (val + up) & 0xFF
            elif ftype == 3:
                out_v = (val + ((left + up) >> 1)) & 0xFF
            elif ftype == 4:
                out_v = (val + _paeth(left, up, up_left)) & 0xFF
            else:
                raise ValueError(f"Unknown PNG scanline filter {ftype}")
            recon[row_out + x] = out_v
        src += stride

    if bpp == 4:
        return width, height, recon
    rgba = bytearray(width * height * 4)
    for i in range(width * height):
        rgba[i * 4 : i * 4 + 3] = recon[i * 3 : i * 3 + 3]
        rgba[i * 4 + 3] = 255
    return width, height, rgba


def inspect_png(path: Path) -> dict[str, Any]:
    """§120 & §138 Inspect PNG dimensions, alpha channel, CRC integrity, and pixel variance."""
    target = Path(path)
    if not target.is_file():
        return {"valid": False, "error": "file_missing"}
    try:
        width, height, rgba = read_rgba_png(target)
    except Exception as exc:
        return {"valid": False, "error": f"{type(exc).__name__}: {exc}"}

    total_px = max(1, width * height)
    step = max(1, total_px // 2000)
    lum_samples: list[float] = []
    transparent_px = 0
    for idx in range(0, total_px, step):
        o = idx * 4
        r, g, b, a = rgba[o], rgba[o + 1], rgba[o + 2], rgba[o + 3]
        if a < 255:
            transparent_px += 1
        lum_samples.append(0.299 * r + 0.587 * g + 0.114 * b)
    mean_lum = sum(lum_samples) / max(1, len(lum_samples))
    variance = sum((v - mean_lum) ** 2 for v in lum_samples) / max(1, len(lum_samples))
    return {
        "valid": True,
        "format": "png",
        "width": width,
        "height": height,
        "has_transparency": transparent_px > 0,
        "luminance_std": round(math.sqrt(variance), 3),
        "non_blank": variance > 1.0 or transparent_px > 0,
        "size_bytes": target.stat().st_size,
    }


def write_ppm(path: Path, width: int, height: int, rgba_bytes: bytes | bytearray) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rgb = bytearray(width * height * 3)
    for i in range(width * height):
        rgb[i * 3 : i * 3 + 3] = rgba_bytes[i * 4 : i * 4 + 3]
    header = f"P6\n{width} {height}\n255\n".encode("ascii")
    out.write_bytes(header + bytes(rgb))
    return out


def read_ppm_as_rgba(path: Path) -> tuple[int, int, bytearray]:
    raw = Path(path).read_bytes()
    if not raw.startswith(b"P6"):
        raise ValueError("Only binary P6 PPM is supported.")
    idx = 2
    tokens: list[bytes] = []
    while len(tokens) < 3 and idx < len(raw):
        while idx < len(raw) and raw[idx : idx + 1] in {b" ", b"\t", b"\r", b"\n"}:
            idx += 1
        if idx < len(raw) and raw[idx : idx + 1] == b"#":
            while idx < len(raw) and raw[idx : idx + 1] != b"\n":
                idx += 1
            continue
        start = idx
        while idx < len(raw) and raw[idx : idx + 1] not in {b" ", b"\t", b"\r", b"\n"}:
            idx += 1
        if idx > start:
            tokens.append(raw[start:idx])
    idx += 1  # single whitespace byte after maxval
    width, height = int(tokens[0]), int(tokens[1])
    rgb = raw[idx : idx + width * height * 3]
    rgba = bytearray(width * height * 4)
    for i in range(width * height):
        rgba[i * 4 : i * 4 + 3] = rgb[i * 3 : i * 3 + 3]
        rgba[i * 4 + 3] = 255
    return width, height, rgba


def resize_rgba(width: int, height: int, rgba: bytes | bytearray, new_w: int, new_h: int) -> bytearray:
    out = bytearray(new_w * new_h * 4)
    for ny in range(new_h):
        sy = min(height - 1, int(ny * height / new_h))
        for nx in range(new_w):
            sx = min(width - 1, int(nx * width / new_w))
            src_o = (sy * width + sx) * 4
            dst_o = (ny * new_w + nx) * 4
            out[dst_o : dst_o + 4] = rgba[src_o : src_o + 4]
    return out


def crop_rgba(width: int, height: int, rgba: bytes | bytearray, x: int, y: int, w: int, h: int) -> tuple[int, int, bytearray]:
    x0, y0 = max(0, x), max(0, y)
    x1, y1 = min(width, x0 + w), min(height, y0 + h)
    cw, ch = max(1, x1 - x0), max(1, y1 - y0)
    out = bytearray(cw * ch * 4)
    for row in range(ch):
        src_o = ((y0 + row) * width + x0) * 4
        dst_o = row * cw * 4
        out[dst_o : dst_o + cw * 4] = rgba[src_o : src_o + cw * 4]
    return cw, ch, out


def remove_corner_background_rgba(width: int, height: int, rgba: bytes | bytearray, tolerance: int = 24) -> bytearray:
    """§120 Key out solid background matching top-left corner pixel into alpha=0."""
    bg_r, bg_g, bg_b = rgba[0], rgba[1], rgba[2]
    out = bytearray(rgba)
    for i in range(width * height):
        o = i * 4
        if abs(out[o] - bg_r) <= tolerance and abs(out[o + 1] - bg_g) <= tolerance and abs(out[o + 2] - bg_b) <= tolerance:
            out[o + 3] = 0
    return out


def extract_palette_png(path: Path, top_k: int = 6) -> list[dict[str, Any]]:
    """§120 Extract quantized dominant hex colors from a PNG image."""
    w, h, rgba = read_rgba_png(path)
    counts: dict[tuple[int, int, int], int] = {}
    total = 0
    for i in range(0, w * h, max(1, (w * h) // 5000)):
        o = i * 4
        if rgba[o + 3] < 32:
            continue
        q = ((rgba[o] // 16) * 16, (rgba[o + 1] // 16) * 16, (rgba[o + 2] // 16) * 16)
        counts[q] = counts.get(q, 0) + 1
        total += 1
    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:top_k]
    return [
        {
            "hex": f"#{r:02x}{g:02x}{b:02x}",
            "rgb": [r, g, b],
            "share": round(cnt / max(1, total), 4),
        }
        for (r, g, b), cnt in ranked
    ]


def compare_png_files(path_a: Path, path_b: Path, diff_out: Path | None = None) -> dict[str, Any]:
    """§120 Pixel-level comparison between two PNG variants without modifying originals."""
    wa, ha, ra = read_rgba_png(path_a)
    wb, hb, rb = read_rgba_png(path_b)
    if (wa, ha) != (wb, hb):
        rb = resize_rgba(wb, hb, rb, wa, ha)
    diff_buf = bytearray(wa * ha * 4)
    changed = 0
    abs_err = 0
    for i in range(wa * ha):
        o = i * 4
        dr = abs(ra[o] - rb[o])
        dg = abs(ra[o + 1] - rb[o + 1])
        db = abs(ra[o + 2] - rb[o + 2])
        dmax = max(dr, dg, db)
        abs_err += dr + dg + db
        if dmax > 4:
            changed += 1
            diff_buf[o : o + 4] = bytes((255, min(255, 60 + dmax), 60, 255))
        else:
            gray = int(0.3 * ra[o] + 0.59 * ra[o + 1] + 0.11 * ra[o + 2]) // 3
            diff_buf[o : o + 4] = bytes((gray, gray, gray, 255))
    if diff_out is not None:
        write_rgba_png(diff_out, wa, ha, diff_buf)
    total_px = max(1, wa * ha)
    return {
        "width": wa,
        "height": ha,
        "changed_pixels": changed,
        "changed_ratio": round(changed / total_px, 5),
        "mean_channel_mae": round(abs_err / (total_px * 3), 3),
        "diff_image": str(diff_out) if diff_out else "",
    }


# ------------------------------------------------ SVG Inspector & Rasterizer


def _parse_hex_color(value: str | None, default: tuple[int, int, int, int] = (30, 41, 59, 255)) -> tuple[int, int, int, int]:
    if not value:
        return default
    v = value.strip().lower()
    if v in {"none", "transparent"}:
        return (0, 0, 0, 0)
    named = {
        "white": (255, 255, 255, 255),
        "black": (15, 23, 42, 255),
        "red": (239, 68, 68, 255),
        "green": (34, 197, 94, 255),
        "blue": (59, 130, 246, 255),
        "cyan": (56, 214, 197, 255),
        "orange": (249, 115, 22, 255),
    }
    if v in named:
        return named[v]
    if v.startswith("#"):
        h = v[1:]
        if len(h) == 3 and all(c in "0123456789abcdef" for c in h):
            return (int(h[0] * 2, 16), int(h[1] * 2, 16), int(h[2] * 2, 16), 255)
        if len(h) == 6 and all(c in "0123456789abcdef" for c in h):
            return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), 255)
    return default


def _num_attr(elem: ET.Element, name: str, default: float = 0.0) -> float:
    raw = elem.attrib.get(name, "").strip().replace("px", "")
    if not raw or raw.endswith("%"):
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _blend_pixel(buf: bytearray, width: int, height: int, x: int, y: int, color: tuple[int, int, int, int]) -> None:
    if x < 0 or y < 0 or x >= width or y >= height or color[3] == 0:
        return
    o = (y * width + x) * 4
    sa = color[3] / 255.0
    da = buf[o + 3] / 255.0
    out_a = sa + da * (1.0 - sa)
    if out_a <= 0:
        return
    buf[o] = int((color[0] * sa + buf[o] * da * (1.0 - sa)) / out_a)
    buf[o + 1] = int((color[1] * sa + buf[o + 1] * da * (1.0 - sa)) / out_a)
    buf[o + 2] = int((color[2] * sa + buf[o + 2] * da * (1.0 - sa)) / out_a)
    buf[o + 3] = int(out_a * 255)


def _draw_line(buf: bytearray, w: int, h: int, x0: int, y0: int, x1: int, y1: int, color: tuple[int, int, int, int], thickness: int = 2) -> None:
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx = 1 if x0 < x1 else -1
    sy = 1 if y0 < y1 else -1
    err = dx + dy
    rad = max(0, (thickness - 1) // 2)
    while True:
        for oy in range(-rad, rad + 1):
            for ox in range(-rad, rad + 1):
                _blend_pixel(buf, w, h, x0 + ox, y0 + oy, color)
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy


def _draw_text_5x7(buf: bytearray, w: int, h: int, x: int, y: int, text: str, color: tuple[int, int, int, int], scale: int = 2) -> None:
    cursor_x = x
    for ch in text.upper()[:64]:
        glyph = _FONT_5X7.get(ch, _FONT_5X7[" "])
        for row_idx, row_bits in enumerate(glyph):
            for col_idx in range(5):
                if row_bits & (1 << (4 - col_idx)):
                    for sy in range(scale):
                        for sx in range(scale):
                            _blend_pixel(buf, w, h, cursor_x + col_idx * scale + sx, y + row_idx * scale + sy, color)
        cursor_x += 6 * scale


def inspect_svg(path: Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        return {"valid": False, "error": "file_missing"}
    try:
        tree = ET.parse(target)
        root = tree.getroot()
    except ET.ParseError as exc:
        return {"valid": False, "error": f"invalid_xml: {exc}"}
    tag = root.tag.split("}")[-1]
    if tag != "svg":
        return {"valid": False, "error": f"expected <svg> root, got <{tag}>"}
    view_box = root.attrib.get("viewBox", "")
    width = _num_attr(root, "width", 0.0)
    height = _num_attr(root, "height", 0.0)
    if (width <= 0 or height <= 0) and view_box:
        parts = [float(p) for p in re.split(r"[\s,]+", view_box.strip()) if p]
        if len(parts) == 4:
            width, height = parts[2], parts[3]
    elem_count = sum(1 for _ in root.iter())
    has_title = any(el.tag.split("}")[-1] == "title" and (el.text or "").strip() for el in root.iter())
    return {
        "valid": elem_count >= 2 and width > 0 and height > 0,
        "format": "svg",
        "editable_vector": True,
        "width": int(width),
        "height": int(height),
        "viewBox": view_box,
        "element_count": elem_count,
        "has_accessible_title": has_title,
        "size_bytes": target.stat().st_size,
    }


def render_svg_to_png(
    svg_path: Path,
    png_path: Path,
    *,
    prefer_external_tool: bool = True,
    forced_external_binary: str | None = None,
) -> dict[str, Any]:
    """Render an editable SVG into a PNG preview using ImageMagick if present or pure-Python fallback."""
    svg_info = inspect_svg(svg_path)
    if not svg_info.get("valid"):
        return {"rendered": False, "error": svg_info.get("error", "invalid_svg"), "tool_used": "none"}

    external_error = ""
    if prefer_external_tool:
        convert_bin = forced_external_binary if forced_external_binary is not None else shutil.which("convert")
        if convert_bin:
            try:
                Path(png_path).parent.mkdir(parents=True, exist_ok=True)
                proc = subprocess.run(
                    [convert_bin, "-background", "none", str(svg_path), f"PNG32:{png_path}"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if proc.returncode == 0 and inspect_png(png_path).get("valid"):
                    return {
                        "rendered": True,
                        "tool_used": "imagemagick_convert",
                        "output": str(png_path),
                        "fallback_used": False,
                    }
                external_error = (proc.stderr or proc.stdout or f"exit={proc.returncode}").strip()[:200]
            except (OSError, subprocess.SubprocessError) as exc:
                external_error = f"{type(exc).__name__}: {exc}"

    # Pure-Python deterministic SVG primitive rasterizer.
    tree = ET.parse(svg_path)
    root = tree.getroot()
    w = max(32, min(1600, int(svg_info["width"] or 640)))
    h = max(32, min(1200, int(svg_info["height"] or 360)))
    buf = bytearray(w * h * 4)

    for elem in root.iter():
        kind = elem.tag.split("}")[-1]
        fill = _parse_hex_color(elem.attrib.get("fill"), default=(56, 214, 197, 255))
        stroke = _parse_hex_color(elem.attrib.get("stroke"), default=(0, 0, 0, 0))
        sw = max(1, int(_num_attr(elem, "stroke-width", 2.0)))
        if kind == "rect":
            rx = int(_num_attr(elem, "x", 0))
            ry = int(_num_attr(elem, "y", 0))
            rw = int(_num_attr(elem, "width", w))
            rh = int(_num_attr(elem, "height", h))
            for py in range(max(0, ry), min(h, ry + rh)):
                for px in range(max(0, rx), min(w, rx + rw)):
                    _blend_pixel(buf, w, h, px, py, fill)
            if stroke[3] > 0 and rw > 1 and rh > 1:
                _draw_line(buf, w, h, rx, ry, rx + rw - 1, ry, stroke, sw)
                _draw_line(buf, w, h, rx + rw - 1, ry, rx + rw - 1, ry + rh - 1, stroke, sw)
                _draw_line(buf, w, h, rx + rw - 1, ry + rh - 1, rx, ry + rh - 1, stroke, sw)
                _draw_line(buf, w, h, rx, ry + rh - 1, rx, ry, stroke, sw)
        elif kind == "circle":
            cx = int(_num_attr(elem, "cx", w // 2))
            cy = int(_num_attr(elem, "cy", h // 2))
            rad = int(_num_attr(elem, "r", 20))
            r2 = rad * rad
            for py in range(max(0, cy - rad), min(h, cy + rad + 1)):
                for px in range(max(0, cx - rad), min(w, cx + rad + 1)):
                    if (px - cx) ** 2 + (py - cy) ** 2 <= r2:
                        _blend_pixel(buf, w, h, px, py, fill)
        elif kind == "line":
            x1 = int(_num_attr(elem, "x1", 0))
            y1 = int(_num_attr(elem, "y1", 0))
            x2 = int(_num_attr(elem, "x2", 0))
            y2 = int(_num_attr(elem, "y2", 0))
            _draw_line(buf, w, h, x1, y1, x2, y2, stroke if stroke[3] else fill, sw)
        elif kind in {"polyline", "polygon"}:
            pts_raw = [p for p in re.split(r"[\s,]+", elem.attrib.get("points", "").strip()) if p]
            pts = [(int(float(pts_raw[i])), int(float(pts_raw[i + 1]))) for i in range(0, len(pts_raw) - 1, 2)]
            col = stroke if stroke[3] else fill
            for idx in range(len(pts) - 1):
                _draw_line(buf, w, h, pts[idx][0], pts[idx][1], pts[idx + 1][0], pts[idx + 1][1], col, sw)
            if kind == "polygon" and len(pts) >= 3:
                _draw_line(buf, w, h, pts[-1][0], pts[-1][1], pts[0][0], pts[0][1], col, sw)
        elif kind == "text" and (elem.text or "").strip():
            tx = int(_num_attr(elem, "x", 16))
            ty = max(4, int(_num_attr(elem, "y", 24)) - 12)
            fsize = _num_attr(elem, "font-size", 16.0)
            scale = max(1, min(4, round(fsize / 10.0)))
            tcol = _parse_hex_color(elem.attrib.get("fill"), default=(240, 245, 255, 255))
            _draw_text_5x7(buf, w, h, tx, ty, (elem.text or "").strip(), tcol, scale=scale)

    write_rgba_png(png_path, w, h, buf)
    return {
        "rendered": True,
        "tool_used": "python_svg_rasterizer",
        "output": str(png_path),
        "fallback_used": True,
        "external_tool_error": external_error,
        "limitation": "Complex SVG path curves and CSS filters are approximated when ImageMagick/Inkscape is absent.",
    }


# -------------------------------------------- Audio (WAV), Subtitles & Video


def write_pcm_wav(
    path: Path,
    *,
    duration_seconds: float = 2.0,
    sample_rate: int = 22050,
    notes_hz: tuple[float, ...] = (440.0, 554.37, 659.25),
) -> Path:
    """Synthesize a clean 16-bit PCM mono WAV audio cue/bed using stdlib `wave`."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    total_frames = max(1, int(duration_seconds * sample_rate))
    seg = max(1, total_frames // max(1, len(notes_hz)))
    samples = bytearray()
    for i in range(total_frames):
        freq = notes_hz[min(len(notes_hz) - 1, i // seg)]
        env = min(1.0, (i % seg) / max(1.0, sample_rate * 0.03), (seg - (i % seg)) / max(1.0, sample_rate * 0.05))
        val = int(11000 * env * math.sin(2.0 * math.pi * freq * (i / sample_rate)))
        samples.extend(struct.pack("<h", max(-32767, min(32767, val))))
    with wave.open(str(out), "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(bytes(samples))
    return out


def inspect_wav(path: Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        return {"valid": False, "error": "file_missing"}
    try:
        with wave.open(str(target), "rb") as wf:
            channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            rate = wf.getframerate()
            nframes = wf.getnframes()
            raw = wf.readframes(min(nframes, 4096))
    except (wave.Error, EOFError, OSError) as exc:
        return {"valid": False, "error": f"{type(exc).__name__}: {exc}"}
    peak = 0
    if sampwidth == 2 and len(raw) >= 2:
        vals = struct.unpack(f"<{len(raw) // 2}h", raw[: (len(raw) // 2) * 2])
        peak = max((abs(v) for v in vals), default=0)
    duration = round(nframes / max(1, rate), 3)
    return {
        "valid": rate > 0 and nframes > 0,
        "format": "wav",
        "channels": channels,
        "sample_width_bytes": sampwidth,
        "sample_rate_hz": rate,
        "frames": nframes,
        "duration_seconds": duration,
        "peak_amplitude": peak,
        "non_silent": peak > 10,
    }


def _fmt_srt_ts(seconds: float) -> str:
    ms_total = max(0, round(seconds * 1000))
    hrs, rem = divmod(ms_total, 3_600_000)
    mins, rem = divmod(rem, 60_000)
    secs, ms = divmod(rem, 1000)
    return f"{hrs:02d}:{mins:02d}:{secs:02d},{ms:03d}"


def write_srt_subtitles(path: Path, cues: list[dict[str, Any]]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    blocks: list[str] = []
    for idx, cue in enumerate(cues, start=1):
        start = _fmt_srt_ts(float(cue["start"]))
        end = _fmt_srt_ts(float(cue["end"]))
        text = str(cue["text"]).strip()
        blocks.append(f"{idx}\n{start} --> {end}\n{text}\n")
    out.write_text("\n".join(blocks), encoding="utf-8")
    return out


def inspect_srt(path: Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        return {"valid": False, "error": "file_missing"}
    text = target.read_text(encoding="utf-8", errors="replace")
    arrows = re.findall(r"(\d{2}:\d{2}:\d{2},\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2},\d{3})", text)
    return {"valid": len(arrows) >= 1, "cue_count": len(arrows), "format": "srt"}


def _riff_chunk(fourcc: bytes, payload: bytes) -> bytes:
    pad = b"\x00" if (len(payload) % 2 == 1) else b""
    return fourcc + struct.pack("<I", len(payload)) + payload + pad


def _riff_list(list_type: bytes, payload: bytes) -> bytes:
    return _riff_chunk(b"LIST", list_type + payload)


def write_uncompressed_avi(
    path: Path,
    frame_png_paths: list[Path],
    *,
    fps: int = 4,
    wav_path: Path | None = None,
) -> Path:
    """Assemble PNG frames + optional 16-bit mono WAV into a spec-compliant RIFF AVI video."""
    if not frame_png_paths:
        raise ValueError("At least one frame is required to assemble an AVI video.")
    w0, h0, _ = read_rgba_png(frame_png_paths[0])
    # Pad width to multiple of 4 bytes per DIB scanline rule.
    w = w0 - (w0 % 4) or 4
    h = h0 - (h0 % 2) or 2
    frame_bytes_list: list[bytes] = []
    row_stride = w * 3
    for fp in frame_png_paths:
        fw, fh, rgba = read_rgba_png(fp)
        if (fw, fh) != (w, h):
            rgba = resize_rgba(fw, fh, rgba, w, h)
        # DIB uncompressed frames store bottom-up BGR24 rows.
        bgr = bytearray(w * h * 3)
        for y in range(h):
            src_y = h - 1 - y
            for x in range(w):
                so = (src_y * w + x) * 4
                do = (y * w + x) * 3
                bgr[do] = rgba[so + 2]
                bgr[do + 1] = rgba[so + 1]
                bgr[do + 2] = rgba[so]
        frame_bytes_list.append(bytes(bgr))

    pcm_data = b""
    audio_rate = 22050
    if wav_path is not None and Path(wav_path).is_file():
        with wave.open(str(wav_path), "rb") as wf:
            if wf.getnchannels() == 1 and wf.getsampwidth() == 2:
                audio_rate = wf.getframerate()
                pcm_data = wf.readframes(wf.getnframes())

    n_frames = len(frame_bytes_list)
    frame_size = row_stride * h
    usec_per_frame = int(1_000_000 / max(1, fps))
    streams = 2 if pcm_data else 1

    avih = struct.pack(
        "<14I",
        usec_per_frame,
        frame_size * fps,
        0,
        0x10,  # AVIF_HASINDEX
        n_frames,
        0,
        streams,
        frame_size,
        w,
        h,
        0,
        0,
        0,
        0,
    )
    v_strh = struct.pack(
        "<4s4sIHHIIIIIIII4H",
        b"vids",
        b"DIB ",
        0,
        0,
        0,
        0,
        1,
        fps,
        0,
        n_frames,
        frame_size,
        10000,
        0,
        0,
        0,
        w,
        h,
    )
    v_strf = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0, frame_size, 0, 0, 0, 0)
    strl_chunks = _riff_list(b"strl", _riff_chunk(b"strh", v_strh) + _riff_chunk(b"strf", v_strf))

    if pcm_data:
        a_samples = len(pcm_data) // 2
        a_strh = struct.pack(
            "<4s4sIHHIIIIIIII4H",
            b"auds",
            b"\x00\x00\x00\x00",
            0,
            0,
            0,
            0,
            2,
            audio_rate * 2,
            0,
            a_samples,
            len(pcm_data),
            10000,
            2,
            0,
            0,
            0,
            0,
        )
        a_strf = struct.pack("<HHIIHH", 1, 1, audio_rate, audio_rate * 2, 2, 16)
        strl_chunks += _riff_list(b"strl", _riff_chunk(b"strh", a_strh) + _riff_chunk(b"strf", a_strf))

    hdrl = _riff_list(b"hdrl", _riff_chunk(b"avih", avih) + strl_chunks)

    movi_body = bytearray()
    idx_entries = bytearray()
    offset = 4  # relative to 'movi' list type tag
    for fb in frame_bytes_list:
        chunk = _riff_chunk(b"00db", fb)
        idx_entries.extend(struct.pack("<4sIII", b"00db", 0x10, offset, len(fb)))
        movi_body.extend(chunk)
        offset += len(chunk)
    if pcm_data:
        achunk = _riff_chunk(b"01wb", pcm_data)
        idx_entries.extend(struct.pack("<4sIII", b"01wb", 0x10, offset, len(pcm_data)))
        movi_body.extend(achunk)

    movi = _riff_list(b"movi", bytes(movi_body))
    idx1 = _riff_chunk(b"idx1", bytes(idx_entries))
    riff = _riff_chunk(b"RIFF", b"AVI " + hdrl + movi + idx1)

    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(riff)
    return out


def assemble_video_from_assets(
    output_dir: Path,
    frame_pngs: list[Path],
    *,
    fps: int = 4,
    wav_path: Path | None = None,
    prefer_ffmpeg: bool = True,
    forced_ffmpeg_binary: str | None = None,
) -> dict[str, Any]:
    """§121 Assemble scene frames and audio into a verified video file without faking cinematic AI output."""
    missing_inputs = [str(p) for p in frame_pngs if not Path(p).is_file()]
    if missing_inputs:
        return {"assembled": False, "error": f"missing frame assets: {missing_inputs[:3]}"}

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ffmpeg_error = ""
    ffmpeg_bin = forced_ffmpeg_binary if forced_ffmpeg_binary is not None else (shutil.which("ffmpeg") if prefer_ffmpeg else None)

    if ffmpeg_bin:
        mp4_path = output_dir / "explainer.mp4"
        concat_file = output_dir / "frames_concat.txt"
        dur = 1.0 / max(1, fps)
        lines = [f"file '{Path(p).resolve()}'\nduration {dur:.4f}" for p in frame_pngs]
        lines.append(f"file '{Path(frame_pngs[-1]).resolve()}'")
        concat_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        cmd = [ffmpeg_bin, "-y", "-f", "concat", "-safe", "0", "-i", str(concat_file)]
        if wav_path and Path(wav_path).is_file():
            cmd.extend(["-i", str(wav_path), "-shortest"])
        cmd.extend(["-pix_fmt", "yuv420p", str(mp4_path)])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
            if proc.returncode == 0 and mp4_path.is_file() and mp4_path.stat().st_size > 256:
                return {
                    "assembled": True,
                    "video_path": str(mp4_path),
                    "format": "mp4",
                    "tool_used": "ffmpeg",
                    "fallback_used": False,
                    "footage_origin": "automated_procedural_asset_assembly",
                }
            ffmpeg_error = (proc.stderr or proc.stdout or f"exit={proc.returncode}").strip()[:220]
        except (OSError, subprocess.SubprocessError) as exc:
            ffmpeg_error = f"{type(exc).__name__}: {exc}"

    avi_path = output_dir / "explainer.avi"
    write_uncompressed_avi(avi_path, frame_pngs, fps=fps, wav_path=wav_path)

    gif_path_str = ""
    convert_bin = shutil.which("convert")
    if convert_bin:
        gif_path = output_dir / "preview.gif"
        delay_cs = max(5, round(100 / max(1, fps)))
        try:
            proc = subprocess.run(
                [convert_bin, "-delay", str(delay_cs), "-loop", "0", *[str(p) for p in frame_pngs], str(gif_path)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if proc.returncode == 0 and gif_path.is_file():
                gif_path_str = str(gif_path)
        except (OSError, subprocess.SubprocessError):
            pass

    return {
        "assembled": True,
        "video_path": str(avi_path),
        "animated_preview": gif_path_str,
        "format": "avi",
        "tool_used": "python_riff_avi_muxer" + ("+imagemagick_gif" if gif_path_str else ""),
        "fallback_used": bool(ffmpeg_bin),
        "primary_tool_failure": ffmpeg_error,
        "footage_origin": "automated_procedural_asset_assembly",
        "limitation": "Uncompressed RIFF AVI assembled locally because FFmpeg H.264/MP4 encoder is not installed." if not ffmpeg_bin else f"FFmpeg failed ({ffmpeg_error}); recovered via local RIFF AVI muxer.",
    }


def inspect_video(path: Path) -> dict[str, Any]:
    """§121 & §138 Verify video container headers, resolution, frame count, and duration."""
    target = Path(path)
    if not target.is_file():
        return {"valid": False, "error": "file_missing"}
    raw = target.read_bytes()
    if len(raw) < 64:
        return {"valid": False, "error": "truncated_container"}

    if raw[:4] == b"RIFF" and raw[8:12] == b"AVI ":
        avih_idx = raw.find(b"avih")
        if avih_idx < 0 or avih_idx + 8 + 56 > len(raw):
            return {"valid": False, "error": "missing_avih_header"}
        fields = struct.unpack("<14I", raw[avih_idx + 8 : avih_idx + 8 + 56])
        usec_per_frame, _max_bps, _pad, _flags, total_frames, _init, streams, _buf_sz, width, height = fields[:10]
        fps = round(1_000_000 / max(1, usec_per_frame), 2)
        duration = round(total_frames / max(0.01, fps), 3)
        frame_chunks = raw.count(b"00db")
        return {
            "valid": width > 0 and height > 0 and total_frames > 0 and frame_chunks >= total_frames,
            "format": "avi",
            "width": width,
            "height": height,
            "frames": total_frames,
            "streams": streams,
            "fps": fps,
            "duration_seconds": duration,
            "size_bytes": len(raw),
        }

    if raw[4:8] == b"ftyp":
        has_moov = b"moov" in raw
        has_mdat = b"mdat" in raw
        return {
            "valid": has_moov and has_mdat and len(raw) > 256,
            "format": "mp4",
            "has_moov": has_moov,
            "has_mdat": has_mdat,
            "size_bytes": len(raw),
        }

    return {"valid": False, "error": "unsupported_video_container"}


# ------------------------------------ 3D Parametric Geometry & Mesh Validation


def build_parametric_enclosure_mesh(
    width_mm: float = 60.0,
    depth_mm: float = 40.0,
    height_mm: float = 24.0,
) -> tuple[list[tuple[float, float, float]], list[tuple[int, int, int]]]:
    """Construct a closed, outward-oriented watertight triangulated 3D solid (in mm)."""
    hx, hy = width_mm / 2.0, depth_mm / 2.0
    vertices: list[tuple[float, float, float]] = [
        (-hx, -hy, 0.0),
        (hx, -hy, 0.0),
        (hx, hy, 0.0),
        (-hx, hy, 0.0),
        (-hx, -hy, height_mm),
        (hx, -hy, height_mm),
        (hx, hy, height_mm),
        (-hx, hy, height_mm),
    ]
    # 12 outward-oriented counter-clockwise triangles forming a closed 2-manifold:
    faces: list[tuple[int, int, int]] = [
        (0, 2, 1),
        (0, 3, 2),  # bottom (z=0, normal -Z)
        (4, 5, 6),
        (4, 6, 7),  # top (z=height, normal +Z)
        (0, 1, 5),
        (0, 5, 4),  # front (y=-hy, normal -Y)
        (1, 2, 6),
        (1, 6, 5),  # right (x=+hx, normal +X)
        (2, 3, 7),
        (2, 7, 6),  # back (y=+hy, normal +Y)
        (3, 0, 4),
        (3, 4, 7),  # left (x=-hx, normal -X)
    ]
    return vertices, faces


def _face_normal(
    v0: tuple[float, float, float],
    v1: tuple[float, float, float],
    v2: tuple[float, float, float],
) -> tuple[float, float, float, float]:
    ux, uy, uz = v1[0] - v0[0], v1[1] - v0[1], v1[2] - v0[2]
    vx, vy, vz = v2[0] - v0[0], v2[1] - v0[1], v2[2] - v0[2]
    nx = uy * vz - uz * vy
    ny = uz * vx - ux * vz
    nz = ux * vy - uy * vx
    mag = math.sqrt(nx * nx + ny * ny + nz * nz)
    if mag <= 1e-12:
        return (0.0, 0.0, 0.0, 0.0)
    return (nx / mag, ny / mag, nz / mag, 0.5 * mag)


def write_ascii_stl(
    path: Path,
    vertices: list[tuple[float, float, float]],
    faces: list[tuple[int, int, int]],
    solid_name: str = "nova_parametric_part",
) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"solid {solid_name}"]
    for i0, i1, i2 in faces:
        v0, v1, v2 = vertices[i0], vertices[i1], vertices[i2]
        nx, ny, nz, _ = _face_normal(v0, v1, v2)
        lines.append(f"  facet normal {nx:.6f} {ny:.6f} {nz:.6f}")
        lines.append("    outer loop")
        lines.append(f"      vertex {v0[0]:.6f} {v0[1]:.6f} {v0[2]:.6f}")
        lines.append(f"      vertex {v1[0]:.6f} {v1[1]:.6f} {v1[2]:.6f}")
        lines.append(f"      vertex {v2[0]:.6f} {v2[1]:.6f} {v2[2]:.6f}")
        lines.append("    endloop")
        lines.append("  endfacet")
    lines.append(f"endsolid {solid_name}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def write_wavefront_obj(
    path: Path,
    vertices: list[tuple[float, float, float]],
    faces: list[tuple[int, int, int]],
    object_name: str = "nova_parametric_part",
) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# NOVA X Parametric 3D Export", f"o {object_name}"]
    for x, y, z in vertices:
        lines.append(f"v {x:.6f} {y:.6f} {z:.6f}")
    for i0, i1, i2 in faces:
        lines.append(f"f {i0 + 1} {i1 + 1} {i2 + 1}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def inspect_mesh(path: Path) -> dict[str, Any]:
    """§122 & §138 Validate STL or OBJ geometry, manifold watertightness, volume, and bounds."""
    target = Path(path)
    if not target.is_file():
        return {"valid": False, "error": "file_missing"}
    ext = target.suffix.lower()
    vertices: list[tuple[float, float, float]] = []
    faces: list[tuple[int, int, int]] = []

    if ext == ".obj":
        for raw_line in target.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if line.startswith("v "):
                parts = line.split()
                if len(parts) >= 4:
                    vertices.append((float(parts[1]), float(parts[2]), float(parts[3])))
            elif line.startswith("f "):
                idxs = [int(tok.split("/")[0]) - 1 for tok in line.split()[1:]]
                for k in range(1, len(idxs) - 1):
                    faces.append((idxs[0], idxs[k], idxs[k + 1]))
    elif ext == ".stl":
        raw_bytes = target.read_bytes()
        text_head = raw_bytes[:256].decode("utf-8", errors="ignore").lstrip()
        vmap: dict[tuple[float, float, float], int] = {}

        def _vidx(pt: tuple[float, float, float]) -> int:
            q = (round(pt[0], 5), round(pt[1], 5), round(pt[2], 5))
            if q not in vmap:
                vmap[q] = len(vertices)
                vertices.append(q)
            return vmap[q]

        if text_head.startswith("solid") and b"facet" in raw_bytes[:2048]:
            tri: list[int] = []
            for raw_line in raw_bytes.decode("utf-8", errors="replace").splitlines():
                s = raw_line.strip()
                if s.startswith("vertex "):
                    ps = s.split()
                    tri.append(_vidx((float(ps[1]), float(ps[2]), float(ps[3]))))
                    if len(tri) == 3:
                        faces.append((tri[0], tri[1], tri[2]))
                        tri = []
        elif len(raw_bytes) >= 84:
            tri_count = struct.unpack("<I", raw_bytes[80:84])[0]
            offset = 84
            for _ in range(tri_count):
                if offset + 50 > len(raw_bytes):
                    break
                vals = struct.unpack("<12fH", raw_bytes[offset : offset + 50])
                i0 = _vidx((vals[3], vals[4], vals[5]))
                i1 = _vidx((vals[6], vals[7], vals[8]))
                i2 = _vidx((vals[9], vals[10], vals[11]))
                faces.append((i0, i1, i2))
                offset += 50
    else:
        return {"valid": False, "error": f"unsupported_mesh_format:{ext}"}

    if len(vertices) < 4 or len(faces) < 4:
        return {"valid": False, "error": "insufficient_geometry", "vertex_count": len(vertices), "face_count": len(faces)}

    finite_ok = all(all(math.isfinite(c) for c in v) for v in vertices)
    directed_edges: dict[tuple[int, int], int] = {}
    degenerate_faces = 0
    surface_area = 0.0
    signed_volume = 0.0

    for i0, i1, i2 in faces:
        v0, v1, v2 = vertices[i0], vertices[i1], vertices[i2]
        _, _, _, area = _face_normal(v0, v1, v2)
        if area <= 1e-9:
            degenerate_faces += 1
        surface_area += area
        signed_volume += (
            v0[0] * (v1[1] * v2[2] - v1[2] * v2[1])
            - v0[1] * (v1[0] * v2[2] - v1[2] * v2[0])
            + v0[2] * (v1[0] * v2[1] - v1[1] * v2[0])
        ) / 6.0
        for a, b in ((i0, i1), (i1, i2), (i2, i0)):
            directed_edges[(a, b)] = directed_edges.get((a, b), 0) + 1

    boundary_edges = sum(1 for (a, b), cnt in directed_edges.items() if directed_edges.get((b, a), 0) != cnt)
    non_manifold_edges = sum(1 for cnt in directed_edges.values() if cnt > 1)
    watertight = boundary_edges == 0 and non_manifold_edges == 0 and degenerate_faces == 0

    xs = [v[0] for v in vertices]
    ys = [v[1] for v in vertices]
    zs = [v[2] for v in vertices]
    return {
        "valid": finite_ok and degenerate_faces == 0 and abs(signed_volume) > 1e-6,
        "format": ext.lstrip("."),
        "vertex_count": len(vertices),
        "face_count": len(faces),
        "degenerate_faces": degenerate_faces,
        "watertight_manifold": watertight,
        "boundary_edges": boundary_edges,
        "bounding_box_mm": {
            "width": round(max(xs) - min(xs), 4),
            "depth": round(max(ys) - min(ys), 4),
            "height": round(max(zs) - min(zs), 4),
        },
        "surface_area_mm2": round(surface_area, 4),
        "volume_mm3": round(abs(signed_volume), 4),
        "engineering_safety_certified": False,
        "safety_note": "Geometric validity verified only; mechanical load, tolerance, and manufacturing safety require physical/FEA engineering validation (§122).",
    }


# ------------------------------------ Office Documents (.docx, .xlsx, .pdf)


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def write_minimal_docx(path: Path, title: str, sections: list[tuple[str, str]]) -> Path:
    """§131 Write a standards-compliant OpenXML `.docx` document without heavy dependencies."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    paras = [
        f'<w:p><w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>{_xml_escape(title)}</w:t></w:r></w:p>'
    ]
    for heading, body in sections:
        if heading:
            paras.append(f'<w:p><w:r><w:rPr><w:b/><w:sz w:val="24"/></w:rPr><w:t>{_xml_escape(heading)}</w:t></w:r></w:p>')
        for line in body.splitlines():
            if line.strip():
                paras.append(f"<w:p><w:r><w:t>{_xml_escape(line)}</w:t></w:r></w:p>")
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{''.join(paras)}<w:sectPr/></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", doc_xml)
    return out


def inspect_docx(path: Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file() or not zipfile.is_zipfile(target):
        return {"valid": False, "error": "not_a_zip_openxml_package"}
    with zipfile.ZipFile(target, "r") as zf:
        names = set(zf.namelist())
        if "word/document.xml" not in names or "[Content_Types].xml" not in names:
            return {"valid": False, "error": "missing_word_openxml_parts"}
        root = ET.fromstring(zf.read("word/document.xml"))
    texts = [el.text for el in root.iter() if el.tag.endswith("}t") and el.text]
    return {"valid": len(texts) >= 1, "format": "docx", "paragraph_runs": len(texts), "characters": sum(len(t) for t in texts)}


def write_minimal_xlsx(path: Path, sheet_name: str, rows: list[list[Any]]) -> Path:
    """§131 Write a standards-compliant OpenXML `.xlsx` spreadsheet."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    row_xml: list[str] = []
    for r_idx, row in enumerate(rows, start=1):
        cells: list[str] = []
        for c_idx, val in enumerate(row):
            col_letter = chr(ord("A") + (c_idx % 26))
            ref = f"{col_letter}{r_idx}"
            if isinstance(val, int | float) and not isinstance(val, bool) and math.isfinite(float(val)):
                cells.append(f'<c r="{ref}"><v>{val}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{_xml_escape(str(val))}</t></is></c>')
        row_xml.append(f'<row r="{r_idx}">{"".join(cells)}</row>')
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(row_xml)}</sheetData></worksheet>'
    )
    wb_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{_xml_escape(sheet_name[:31])}" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    ctypes = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", ctypes)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("xl/workbook.xml", wb_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return out


def inspect_xlsx(path: Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file() or not zipfile.is_zipfile(target):
        return {"valid": False, "error": "not_a_zip_openxml_package"}
    with zipfile.ZipFile(target, "r") as zf:
        names = set(zf.namelist())
        if "xl/workbook.xml" not in names or "xl/worksheets/sheet1.xml" not in names:
            return {"valid": False, "error": "missing_xlsx_parts"}
        root = ET.fromstring(zf.read("xl/worksheets/sheet1.xml"))
    row_count = sum(1 for el in root.iter() if el.tag.endswith("}row"))
    cell_count = sum(1 for el in root.iter() if el.tag.endswith("}c"))
    return {"valid": row_count >= 1, "format": "xlsx", "rows": row_count, "cells": cell_count}


def _pdf_escape(text: str) -> str:
    ascii_clean = text.encode("latin-1", errors="replace").decode("latin-1")
    return ascii_clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_minimal_pdf(path: Path, title: str, lines: list[str]) -> Path:
    """§131 Write a valid, multi-page printable PDF-1.4 document with exact byte-offset xref."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    wrapped: list[str] = [title, "=" * min(60, len(title)), ""]
    for raw in lines:
        s = raw.rstrip()
        if not s:
            wrapped.append("")
            continue
        while len(s) > 86:
            wrapped.append(s[:86])
            s = s[86:]
        wrapped.append(s)

    lines_per_page = 44
    pages = [wrapped[i : i + lines_per_page] for i in range(0, max(1, len(wrapped)), lines_per_page)]
    objects: list[bytes] = []

    # 1: Catalog, 2: Pages, 3: Font
    page_obj_ids = [4 + idx * 2 for idx in range(len(pages))]
    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for idx, page_lines in enumerate(pages):
        page_id = 4 + idx * 2
        content_id = page_id + 1
        ops = ["BT", "/F1 11 Tf", "50 750 Td", "15 TL"]
        for line in page_lines:
            ops.append(f"({_pdf_escape(line)}) Tj T*")
        ops.append("ET")
        stream_bytes = "\n".join(ops).encode("latin-1")
        page_dict = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        content_obj = f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii") + stream_bytes + b"\nendstream"
        objects.append(page_dict)
        objects.append(content_obj)

    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj_num, obj_body in enumerate(objects, start=1):
        offsets.append(len(buf))
        buf.extend(f"{obj_num} 0 obj\n".encode("ascii"))
        buf.extend(obj_body)
        buf.extend(b"\nendobj\n")

    xref_pos = len(buf)
    buf.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    buf.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    out.write_bytes(bytes(buf))
    return out


def inspect_pdf(path: Path) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        return {"valid": False, "error": "file_missing"}
    raw = target.read_bytes()
    has_hdr = raw.startswith(b"%PDF-1.")
    has_xref = b"xref" in raw and b"%%EOF" in raw[-64:]
    pages = len(re.findall(rb"/Type\s*/Page\b", raw))
    return {"valid": has_hdr and has_xref and pages >= 1, "format": "pdf", "pages": pages, "size_bytes": len(raw)}


# ------------------------------ §132 Universal Format Conversion & File Repair


class UniversalFormatConverter:
    """§132 Safe format detection, non-destructive repair, and loss-aware conversion."""

    NEVER_EXECUTE_UNKNOWN_FILES = True

    def inspect_file(self, path: Path) -> dict[str, Any]:
        """Inspect a file using magic bytes and safe parsers without ever executing it."""
        target = Path(path)
        if not target.is_file():
            return {"exists": False, "valid": False, "error": "file_not_found"}
        head = target.read_bytes()[:64]
        ext = target.suffix.lower()
        sha = hashlib.sha256(target.read_bytes()).hexdigest()
        base = {
            "exists": True,
            "path": str(target),
            "extension": ext,
            "size_bytes": target.stat().st_size,
            "sha256": sha,
            "executed_to_inspect": False,
        }
        if head.startswith(PNG_SIGNATURE):
            return {**base, **inspect_png(target)}
        if head.startswith(b"%PDF-"):
            return {**base, **inspect_pdf(target)}
        if head[:4] == b"RIFF" and head[8:12] == b"WAVE":
            return {**base, **inspect_wav(target)}
        if head[:4] == b"RIFF" and head[8:12] == b"AVI ":
            return {**base, **inspect_video(target)}
        if ext == ".docx":
            return {**base, **inspect_docx(target)}
        if ext == ".xlsx":
            return {**base, **inspect_xlsx(target)}
        if ext == ".svg":
            return {**base, **inspect_svg(target)}
        if ext in {".stl", ".obj"}:
            return {**base, **inspect_mesh(target)}
        if ext == ".srt":
            return {**base, **inspect_srt(target)}
        if ext in {".sqlite", ".sqlite3", ".db"}:
            header = target.read_bytes()[:16]
            if header != b"SQLite format 3\x00":
                return {**base, "valid": False, "format": "sqlite", "error": "invalid_sqlite_header"}
            try:
                with sqlite3.connect(target) as conn:
                    integrity = conn.execute("PRAGMA integrity_check").fetchone()
                    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
                return {**base, "valid": bool(integrity and integrity[0] == "ok"), "format": "sqlite", "tables": tables}
            except sqlite3.Error as exc:
                return {**base, "valid": False, "format": "sqlite", "error": str(exc)}

        # Text / structured data diagnostics
        raw = target.read_bytes()
        try:
            text = raw.decode("utf-8")
            encoding = "utf-8-bom" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
            encoding_ok = True
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
            encoding = "non-utf8"
            encoding_ok = False

        if ext == ".json":
            try:
                parsed = json.loads(text.lstrip("\ufeff"))
                return {**base, "valid": encoding_ok, "format": "json", "encoding": encoding, "root_type": type(parsed).__name__}
            except ValueError as exc:
                return {**base, "valid": False, "format": "json", "encoding": encoding, "parse_error": str(exc)}
        if ext == ".csv":
            rows = list(csv.reader(text.lstrip("\ufeff").splitlines()))
            widths = {len(r) for r in rows if r}
            return {
                **base,
                "valid": encoding_ok and len(rows) >= 1 and len(widths) <= 1,
                "format": "csv",
                "encoding": encoding,
                "rows": len(rows),
                "ragged_columns": len(widths) > 1,
            }
        return {**base, "valid": encoding_ok, "format": ext.lstrip(".") or "text", "encoding": encoding, "lines": len(text.splitlines())}

    def repair_file(self, source: Path, output: Path) -> dict[str, Any]:
        """§132 Repair common encoding, BOM, trailing-comma JSON, and ragged CSV issues while preserving source."""
        src = Path(source)
        out = Path(output)
        if src.resolve() == out.resolve():
            raise ValueError("Refusing to overwrite original file during repair; choose a distinct output path.")
        raw = src.read_bytes()
        issues_fixed: list[str] = []
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
            issues_fixed.append("stripped_utf8_bom")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")
            issues_fixed.append("transcoded_latin1_to_utf8")

        if "\r\n" in text:
            text = text.replace("\r\n", "\n")
            issues_fixed.append("normalized_crlf_line_endings")

        ext = src.suffix.lower()
        if ext == ".json":
            cleaned = re.sub(r",\s*([}\]])", r"\1", text)
            if cleaned != text:
                issues_fixed.append("removed_trailing_json_commas")
            parsed = json.loads(cleaned)
            text = json.dumps(parsed, indent=2, ensure_ascii=False) + "\n"
        elif ext == ".csv":
            rows = [r for r in csv.reader(text.splitlines()) if any(cell.strip() for cell in r)]
            if rows:
                target_cols = max(len(r) for r in rows)
                if any(len(r) != target_cols for r in rows):
                    rows = [r + [""] * (target_cols - len(r)) for r in rows]
                    issues_fixed.append("padded_ragged_csv_rows")
                out.parent.mkdir(parents=True, exist_ok=True)
                with out.open("w", encoding="utf-8", newline="") as handle:
                    csv.writer(handle).writerows(rows)
                return {
                    "repaired": True,
                    "source_preserved": src.is_file(),
                    "output": str(out),
                    "issues_fixed": issues_fixed,
                    "validation": self.inspect_file(out),
                }

        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return {
            "repaired": True,
            "source_preserved": src.is_file(),
            "output": str(out),
            "issues_fixed": issues_fixed,
            "validation": self.inspect_file(out),
        }

    def convert(self, source: Path, target: Path) -> dict[str, Any]:
        """§132 Convert between compatible formats and disclose any information loss."""
        src = Path(source)
        dst = Path(target)
        if not src.is_file():
            return {"converted": False, "error": "source_not_found"}
        if src.resolve() == dst.resolve():
            return {"converted": False, "error": "refusing_to_overwrite_source"}

        s_ext = src.suffix.lower()
        t_ext = dst.suffix.lower()
        dst.parent.mkdir(parents=True, exist_ok=True)
        info_lost: list[str] = []
        tool_used = "python_stdlib"

        if s_ext == ".csv" and t_ext == ".json":
            with src.open("r", encoding="utf-8", newline="") as handle:
                records = list(csv.DictReader(handle))
            dst.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            info_lost.append("CSV cell values remain strings unless explicitly typed.")
        elif s_ext == ".json" and t_ext == ".csv":
            loaded = json.loads(src.read_text(encoding="utf-8"))
            if not isinstance(loaded, list) or not all(isinstance(r, dict) for r in loaded):
                return {"converted": False, "error": "json_to_csv_requires_array_of_objects"}
            headers = list(dict.fromkeys(k for row in loaded for k in row))
            with dst.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=headers)
                writer.writeheader()
                for row in loaded:
                    writer.writerow({k: json.dumps(v) if isinstance(v, dict | list) else v for k, v in row.items()})
            info_lost.append("Nested JSON objects/types are flattened to scalar text columns.")
        elif s_ext == ".csv" and t_ext == ".xlsx":
            with src.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            write_minimal_xlsx(dst, "Data", rows)
        elif s_ext == ".csv" and t_ext in {".sqlite", ".sqlite3", ".db"}:
            with src.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
            if not rows:
                return {"converted": False, "error": "empty_csv"}
            cols = [re.sub(r"[^a-zA-Z0-9_]", "_", c.strip()) or f"col_{i}" for i, c in enumerate(rows[0])]
            dst.unlink(missing_ok=True)
            with sqlite3.connect(dst) as conn:
                col_defs = ", ".join(f'"{c}" TEXT' for c in cols)
                conn.execute(f"CREATE TABLE imported_data ({col_defs})")
                placeholders = ", ".join("?" for _ in cols)
                conn.executemany(f"INSERT INTO imported_data VALUES ({placeholders})", [r[: len(cols)] + [""] * max(0, len(cols) - len(r)) for r in rows[1:]])
                conn.commit()
            tool_used = "sqlite3"
        elif s_ext == ".md" and t_ext == ".html":
            md = src.read_text(encoding="utf-8")
            body_lines: list[str] = []
            for line in md.splitlines():
                if line.startswith("# "):
                    body_lines.append(f"<h1>{_xml_escape(line[2:].strip())}</h1>")
                elif line.startswith("## "):
                    body_lines.append(f"<h2>{_xml_escape(line[3:].strip())}</h2>")
                elif line.startswith("- "):
                    body_lines.append(f"<li>{_xml_escape(line[2:].strip())}</li>")
                elif line.strip():
                    body_lines.append(f"<p>{_xml_escape(line.strip())}</p>")
            html = (
                "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                f"<title>{_xml_escape(src.stem)}</title></head><body>\n"
                + "\n".join(body_lines)
                + "\n</body></html>\n"
            )
            dst.write_text(html, encoding="utf-8")
        elif s_ext == ".md" and t_ext == ".docx":
            md = src.read_text(encoding="utf-8")
            lines = md.splitlines()
            title = lines[0].lstrip("# ").strip() if lines else src.stem
            write_minimal_docx(dst, title, [("Document Body", "\n".join(lines[1:]))])
            info_lost.append("Complex Markdown inline tables or raw HTML blocks are simplified to plain paragraphs.")
        elif s_ext == ".md" and t_ext == ".pdf":
            md = src.read_text(encoding="utf-8")
            lines = md.splitlines()
            title = lines[0].lstrip("# ").strip() if lines else src.stem
            write_minimal_pdf(dst, title, lines[1:])
            info_lost.append("PDF export flattens editable Markdown structure into fixed printable pages.")
        elif s_ext == ".svg" and t_ext == ".png":
            res = render_svg_to_png(src, dst)
            if not res.get("rendered"):
                return {"converted": False, "error": res.get("error", "svg_render_failed")}
            tool_used = str(res["tool_used"])
            info_lost.append("Rasterizing SVG to PNG discards editable vector paths and scene hierarchy.")
        elif s_ext == ".png" and t_ext == ".ppm":
            w, h, rgba = read_rgba_png(src)
            write_ppm(dst, w, h, rgba)
            info_lost.append("PPM (P6) does not preserve the PNG alpha transparency channel.")
        elif s_ext == ".ppm" and t_ext == ".png":
            w, h, rgba = read_ppm_as_rgba(src)
            write_rgba_png(dst, w, h, rgba)
        elif s_ext == ".obj" and t_ext == ".stl":
            verts: list[tuple[float, float, float]] = []
            faces: list[tuple[int, int, int]] = []
            for line in src.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s.startswith("v "):
                    ps = s.split()
                    verts.append((float(ps[1]), float(ps[2]), float(ps[3])))
                elif s.startswith("f "):
                    idxs = [int(tok.split("/")[0]) - 1 for tok in s.split()[1:]]
                    for k in range(1, len(idxs) - 1):
                        faces.append((idxs[0], idxs[k], idxs[k + 1]))
            write_ascii_stl(dst, verts, faces, solid_name=src.stem)
            info_lost.append("STL drops Wavefront OBJ material assignments, UV coordinates, and shared vertex indexing.")
        else:
            return {"converted": False, "error": f"unsupported_conversion_pair:{s_ext}->{t_ext}"}

        validation = self.inspect_file(dst)
        return {
            "converted": bool(validation.get("valid", dst.is_file())),
            "source": str(src),
            "source_preserved": src.is_file(),
            "output": str(dst),
            "tool_used": tool_used,
            "lossless": len(info_lost) == 0,
            "information_lost": info_lost,
            "validation": validation,
        }


__all__ = [
    "PNG_SIGNATURE",
    "UniversalFormatConverter",
    "assemble_video_from_assets",
    "build_parametric_enclosure_mesh",
    "compare_png_files",
    "crop_rgba",
    "extract_palette_png",
    "inspect_docx",
    "inspect_mesh",
    "inspect_pdf",
    "inspect_png",
    "inspect_srt",
    "inspect_svg",
    "inspect_video",
    "inspect_wav",
    "read_ppm_as_rgba",
    "read_rgba_png",
    "remove_corner_background_rgba",
    "render_svg_to_png",
    "resize_rgba",
    "write_ascii_stl",
    "write_minimal_docx",
    "write_minimal_pdf",
    "write_minimal_xlsx",
    "write_pcm_wav",
    "write_ppm",
    "write_rgba_png",
    "write_srt_subtitles",
    "write_uncompressed_avi",
    "write_wavefront_obj",
]
