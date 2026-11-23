import os
from PIL import Image, ImageDraw

def create_shield_icon(size=256):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx, cy = size / 2, size / 2
    w = size * 0.82
    h = size * 0.88

    # Shield polygon coordinates
    # Top flat with beveled corners, curving down to sharp bottom point
    top = cy - h / 2 + 10
    bottom = cy + h / 2 - 8
    left = cx - w / 2
    right = cx + w / 2

    shield_pts = [
        (cx, top),
        (right - 14, top + 6),
        (right, top + 28),
        (right, cy + 10),
        (cx, bottom),
        (left, cy + 10),
        (left, top + 28),
        (left + 14, top + 6),
    ]

    # Background gradient fill (Dark obsidian to slate cyan)
    draw.polygon(shield_pts, fill=(10, 18, 32, 250))

    # Outer glow / border (Kaspersky Emerald #00D084)
    emerald = (0, 208, 132, 255)
    cyan = (0, 240, 255, 255)
    dark_cyan = (0, 140, 180, 180)

    # Thick glowing border
    for thickness in range(int(size * 0.035), 0, -1):
        alpha = int(120 + (135 * (1 - thickness / (size * 0.035))))
        color = (0, 208, 132, alpha)
        draw.polygon(shield_pts, outline=color, width=thickness)

    # Inner decorative shield contour
    inset = size * 0.08
    inner_pts = [
        (cx, top + inset),
        (right - inset - 8, top + inset + 4),
        (right - inset, top + inset + 20),
        (right - inset, cy + 5),
        (cx, bottom - inset),
        (left + inset, cy + 5),
        (left + inset, top + inset + 20),
        (left + inset + 8, top + inset + 4),
    ]
    draw.polygon(inner_pts, outline=(0, 240, 255, 180), width=int(size * 0.015))

    # Center High-Tech Emblem: Modern Crosshair & Core Pulse
    core_rad = size * 0.16
    draw.ellipse(
        [cx - core_rad, cy - core_rad * 0.8, cx + core_rad, cy + core_rad * 1.2],
        fill=(0, 40, 60, 220),
        outline=cyan,
        width=int(size * 0.02)
    )

    # Glowing center core
    small_rad = size * 0.08
    draw.ellipse(
        [cx - small_rad, cy - small_rad * 0.5 + 4, cx + small_rad, cy + small_rad * 0.9 + 4],
        fill=emerald,
        outline=cyan,
        width=int(size * 0.01)
    )

    # Vertical & Horizontal Crosshair tick marks
    tick_len = size * 0.08
    # Top tick
    draw.line([(cx, cy - core_rad * 0.8 - tick_len), (cx, cy - core_rad * 0.8)], fill=cyan, width=int(size * 0.018))
    # Bottom tick
    draw.line([(cx, cy + core_rad * 1.2), (cx, cy + core_rad * 1.2 + tick_len)], fill=cyan, width=int(size * 0.018))
    # Left tick
    draw.line([(cx - core_rad - tick_len, cy + 4), (cx - core_rad, cy + 4)], fill=cyan, width=int(size * 0.018))
    # Right tick
    draw.line([(cx + core_rad, cy + 4), (cx + core_rad + tick_len, cy + 4)], fill=cyan, width=int(size * 0.018))

    return img

def main():
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    base_img = create_shield_icon(256)

    ico_path = os.path.abspath("sentinelgrid.ico")
    base_img.save(
        ico_path,
        format="ICO",
        sizes=sizes
    )
    print(f"Created ICO icon: {ico_path}")

    # Also save PNG for web favicon / app branding
    png_path = os.path.abspath("sentinelgrid.png")
    base_img.save(png_path, format="PNG")
    print(f"Created PNG icon: {png_path}")

    # Copy to frontend public as well
    frontend_public = os.path.abspath(os.path.join("frontend", "public"))
    if os.path.exists(frontend_public):
        base_img.save(os.path.join(frontend_public, "sentinelgrid.ico"), format="ICO", sizes=sizes)
        base_img.save(os.path.join(frontend_public, "sentinelgrid.png"), format="PNG")

if __name__ == "__main__":
    main()
