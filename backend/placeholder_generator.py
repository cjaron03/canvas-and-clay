"""Placeholder image generator for Canvas & Clay setup wizard.

Generates colored placeholder images with text overlays using Pillow.
Used to create demo artwork images during initial setup.
"""
import io
from PIL import Image, ImageDraw, ImageFont


# Color palette for demo artworks
DEMO_COLORS = [
    (65, 105, 225),   # Royal Blue
    (220, 20, 60),    # Crimson
    (50, 205, 50),    # Lime Green
    (255, 165, 0),    # Orange
    (138, 43, 226),   # Blue Violet
]


def generate_placeholder_image(
    width=800,
    height=600,
    background_color=None,
    text=None,
    text_color=(255, 255, 255)
):
    """Generate a colored placeholder image with optional text overlay.

    Args:
        width: Image width in pixels (default 800)
        height: Image height in pixels (default 600)
        background_color: RGB tuple (r, g, b) or None for first palette color
        text: Optional text to overlay on the image
        text_color: RGB tuple for text color (default white)

    Returns:
        bytes: PNG image data as bytes
    """
    if background_color is None:
        background_color = DEMO_COLORS[0]

    # Create image with solid background
    image = Image.new('RGB', (width, height), background_color)
    draw = ImageDraw.Draw(image)

    if text:
        # Try to use a reasonable font size based on image dimensions
        font_size = min(width, height) // 10
        try:
            # Try to load a system font
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
        except (OSError, IOError):
            try:
                # Fallback to another common location
                font = ImageFont.truetype("/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf", font_size)
            except (OSError, IOError):
                # Use default font if system fonts unavailable
                font = ImageFont.load_default()

        # Get text bounding box for centering
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]

        # Center the text
        x = (width - text_width) // 2
        y = (height - text_height) // 2

        # Draw text with slight shadow for readability
        shadow_offset = max(2, font_size // 20)
        shadow_color = tuple(max(0, c - 80) for c in background_color)
        draw.text((x + shadow_offset, y + shadow_offset), text, font=font, fill=shadow_color)
        draw.text((x, y), text, font=font, fill=text_color)

        # Add "PLACEHOLDER" subtitle
        subtitle = "PLACEHOLDER"
        subtitle_font_size = font_size // 3
        try:
            subtitle_font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", subtitle_font_size)
        except (OSError, IOError):
            try:
                subtitle_font = ImageFont.truetype("/usr/share/fonts/dejavu/DejaVuSans.ttf", subtitle_font_size)
            except (OSError, IOError):
                subtitle_font = ImageFont.load_default()

        subtitle_bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
        subtitle_width = subtitle_bbox[2] - subtitle_bbox[0]
        subtitle_x = (width - subtitle_width) // 2
        subtitle_y = y + text_height + 20

        # Muted subtitle color
        subtitle_color = tuple(min(255, c + 60) for c in background_color)
        draw.text((subtitle_x, subtitle_y), subtitle, font=subtitle_font, fill=subtitle_color)

    # Add decorative border
    border_width = 4
    border_color = tuple(min(255, c + 40) for c in background_color)
    draw.rectangle(
        [border_width, border_width, width - border_width - 1, height - border_width - 1],
        outline=border_color,
        width=border_width
    )

    # Convert to bytes
    buffer = io.BytesIO()
    image.save(buffer, format='PNG', compress_level=6)
    buffer.seek(0)
    return buffer.getvalue()


def get_color_for_index(index):
    """Get a color from the palette by index (wraps around).

    Args:
        index: Integer index into the color palette

    Returns:
        tuple: RGB color tuple
    """
    return DEMO_COLORS[index % len(DEMO_COLORS)]


if __name__ == "__main__":
    # Test generation
    for i, color in enumerate(DEMO_COLORS):
        img_bytes = generate_placeholder_image(
            width=800,
            height=600,
            background_color=color,
            text=f"Test Image {i + 1}"
        )
        print(f"Generated image {i + 1}: {len(img_bytes)} bytes")
