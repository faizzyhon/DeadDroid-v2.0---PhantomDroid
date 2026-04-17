"""
Steganography Payload Delivery — unique to DeadDroid.

Hides a payload download URL (or any text) inside a normal-looking
JPEG/PNG image using LSB (Least Significant Bit) steganography.

Use case: Share an innocent-looking image in a social-engineering
simulation. The image contains a hidden URL; a custom extractor
recovers it. The image looks 100% normal to the naked eye.

No other Android pentest tool has steganographic delivery.
"""

import struct
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt, Confirm
from core.utils import PAYLOADS_DIR, log_event

console = Console()

MAGIC_HEADER = b"DDROI"   # 5-byte magic so we can verify during extraction


def _text_to_bits(text: str) -> list[int]:
    data = MAGIC_HEADER + text.encode("utf-8") + b"\x00"
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_text(bits: list[int]) -> Optional[str]:
    chars = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]
        if len(byte_bits) < 8:
            break
        byte = 0
        for b in byte_bits:
            byte = (byte << 1) | b
        chars.append(byte)

    data = bytes(chars)
    if not data.startswith(MAGIC_HEADER):
        return None

    payload = data[len(MAGIC_HEADER):]
    null_idx = payload.find(b"\x00")
    if null_idx == -1:
        return None
    return payload[:null_idx].decode("utf-8", errors="ignore")


def hide_in_image(
    cover_image: Path,
    secret_text: str,
    output_path: Optional[Path] = None,
) -> Optional[Path]:
    """
    Embed secret_text into cover_image using LSB steganography.
    Modifies the least significant bit of each R channel pixel.
    Returns path to the stego image.
    """
    try:
        from PIL import Image
    except ImportError:
        console.print("[red]✘ Pillow not installed.[/]  Run: pip install Pillow")
        return None

    img    = Image.open(cover_image).convert("RGB")
    pixels = list(img.getdata())
    bits   = _text_to_bits(secret_text)

    if len(bits) > len(pixels):
        console.print(
            f"[red]✘ Secret too long ({len(bits)} bits) for image ({len(pixels)} pixels).[/]"
        )
        return None

    new_pixels = []
    for i, px in enumerate(pixels):
        if i < len(bits):
            r = (px[0] & 0xFE) | bits[i]
            new_pixels.append((r, px[1], px[2]))
        else:
            new_pixels.append(px)

    out = output_path or PAYLOADS_DIR / f"stego_{cover_image.stem}.png"
    stego = Image.new("RGB", img.size)
    stego.putdata(new_pixels)
    stego.save(str(out), format="PNG")

    console.print(f"[green]✔ Secret hidden in:[/] {out}")
    console.print(f"[dim]  Image size: {img.size}  |  Secret length: {len(secret_text)} chars[/]")
    log_event(f"Stego image created: {out} | secret_len={len(secret_text)}")
    return out


def extract_from_image(stego_image: Path) -> Optional[str]:
    """Extract a hidden message from a stego image."""
    try:
        from PIL import Image
    except ImportError:
        console.print("[red]✘ Pillow not installed.[/]")
        return None

    img    = Image.open(stego_image).convert("RGB")
    pixels = list(img.getdata())

    # Extract up to 10000 bits (enough for a URL + some overhead)
    bits = [(px[0] & 1) for px in pixels[:10000]]
    result = _bits_to_text(bits)

    if result:
        console.print(f"[green]✔ Hidden message found:[/] [bold]{result}[/]")
    else:
        console.print("[yellow]No DeadDroid steganographic data found in image.[/]")
    return result


def generate_stego_payload_image(
    cover_image: Path,
    payload_url: str,
    output_path: Optional[Path] = None,
) -> Optional[Path]:
    """
    High-level helper: embed a payload URL into a cover image.
    The URL will be extracted by the companion decoder.
    """
    return hide_in_image(cover_image, payload_url, output_path)


def generate_decoder_script() -> Path:
    """
    Generate a standalone Python decoder that anyone can run to extract
    a hidden URL from a stego image (for the target-side extraction demo).
    """
    decoder_code = '''#!/usr/bin/env python3
"""DeadDroid Stego Decoder — extracts hidden URLs from stego images."""
import sys
from PIL import Image

MAGIC = b"DDROI"

def decode(path):
    img    = Image.open(path).convert("RGB")
    pixels = list(img.getdata())
    bits   = [(px[0] & 1) for px in pixels[:80000]]
    chars  = []
    for i in range(0, len(bits), 8):
        bb = bits[i:i+8]
        if len(bb) < 8: break
        b = 0
        for x in bb:
            b = (b << 1) | x
        chars.append(b)
    data = bytes(chars)
    if not data.startswith(MAGIC):
        print("No hidden data found.")
        return
    payload = data[len(MAGIC):]
    null_idx = payload.find(b"\\x00")
    if null_idx == -1:
        print("No hidden data found.")
        return
    print("Hidden message:", payload[:null_idx].decode("utf-8", errors="ignore"))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python decoder.py <image.png>")
        sys.exit(1)
    decode(sys.argv[1])
'''
    path = PAYLOADS_DIR / "stego_decoder.py"
    path.write_text(decoder_code)
    console.print(f"[green]✔ Decoder script saved:[/] {path}")
    return path


def interactive_stego():
    console.rule("[bold cyan]Steganography Payload Delivery[/]")
    console.print(
        "[dim]Hide a payload download URL inside a normal-looking image.\n"
        "The image is visually identical to the original — no one can tell.[/]\n"
    )

    menu = {
        "1": "Hide URL in image",
        "2": "Extract hidden URL from image",
        "3": "Generate standalone decoder script",
        "4": "Back",
    }
    from rich.table import Table
    m = Table(show_header=False, box=None)
    for k, v in menu.items():
        m.add_row(f"[yellow][{k}][/]", v)
    console.print(m)

    choice = Prompt.ask("Select", choices=list(menu.keys()), default="4")

    if choice == "1":
        img_path = Prompt.ask("Cover image path (JPEG or PNG)")
        url      = Prompt.ask("URL or text to hide")
        out      = Prompt.ask("Output path (blank = auto)", default="")
        cover    = Path(img_path.strip('"').strip("'"))
        if not cover.exists():
            console.print("[red]✘ Image not found.[/]")
            return
        hide_in_image(cover, url, Path(out) if out else None)

    elif choice == "2":
        img_path = Prompt.ask("Stego image path")
        stego    = Path(img_path.strip('"').strip("'"))
        if not stego.exists():
            console.print("[red]✘ Image not found.[/]")
            return
        extract_from_image(stego)

    elif choice == "3":
        generate_decoder_script()
