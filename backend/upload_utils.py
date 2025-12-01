"""Security utilities for file upload handling.

This module provides comprehensive file upload validation including:
- Magic byte validation (actual file type detection)
- Filename sanitization (path traversal prevention)
- File size validation
- Image dimension validation
- Thumbnail generation
"""
import os
import re
import io
import secrets
from datetime import datetime, timezone
from PIL import Image
import magic


# Configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB in bytes
MAX_IMAGE_DIMENSION = 8000  # Maximum width or height in pixels
THUMBNAIL_SIZE = (200, 200)  # Thumbnail dimensions
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
ARTWORKS_DIR = os.path.join(UPLOAD_DIR, 'artworks')
THUMBNAILS_DIR = os.path.join(UPLOAD_DIR, 'thumbnails')

# Allowed MIME types and their magic byte signatures
ALLOWED_MIME_TYPES = {
    'image/jpeg': [
        b'\xff\xd8\xff\xe0',  # JPEG/JFIF
        b'\xff\xd8\xff\xe1',  # JPEG/Exif
        b'\xff\xd8\xff\xe2',  # JPEG/Canon
        b'\xff\xd8\xff\xe3',  # JPEG/Samsung
        b'\xff\xd8\xff\xe8',  # JPEG/SPIFF
        b'\xff\xd8\xff\xdb',  # JPEG raw
        b'\xff\xd8\xff\xee',  # JPEG/Adobe
    ],
    'image/png': [
        b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a',  # PNG
    ],
    'image/webp': [
        b'RIFF',  # WebP (must also check for WEBP string at offset 8)
    ],
    'image/avif': [
        b'\x00\x00\x00\x20\x66\x74\x79\x70\x61\x76\x69\x66',  # AVIF
        b'\x00\x00\x00\x18\x66\x74\x79\x70\x61\x76\x69\x66',  # AVIF (variant)
    ],
}

# File extensions for each MIME type
MIME_TO_EXTENSION = {
    'image/jpeg': '.jpg',
    'image/png': '.png',
    'image/webp': '.webp',
    'image/avif': '.avif',
}


class FileValidationError(Exception):
    """Custom exception for file validation errors."""
    pass


def validate_magic_bytes(file_data):
    """Validate file type using magic bytes (file header).

    Args:
        file_data: Binary file data (bytes)

    Returns:
        str: Detected MIME type

    Raises:
        FileValidationError: If file type is not allowed
    """
    if len(file_data) < 12:
        raise FileValidationError("File is too small to validate")

    # Check magic bytes for each allowed type
    for mime_type, signatures in ALLOWED_MIME_TYPES.items():
        for signature in signatures:
            if file_data.startswith(signature):
                # Special handling for WebP (need to verify WEBP string at offset 8)
                if mime_type == 'image/webp':
                    if len(file_data) >= 12 and file_data[8:12] == b'WEBP':
                        return mime_type
                else:
                    return mime_type

    # Use python-magic as fallback for more robust detection
    try:
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_buffer(file_data)

        if detected_mime in ALLOWED_MIME_TYPES:
            return detected_mime
    except Exception:
        pass

    raise FileValidationError(
        "File type not allowed. Only JPG, PNG, WebP, and AVIF images are permitted."
    )


def sanitize_filename(filename):
    """Sanitize filename to prevent path traversal and other attacks.

    Args:
        filename: Original filename

    Returns:
        str: Sanitized filename

    Raises:
        FileValidationError: If filename is invalid
    """
    if not filename:
        raise FileValidationError("Filename cannot be empty")

    # Remove any path components (prevent directory traversal)
    filename = os.path.basename(filename)

    # Remove null bytes
    filename = filename.replace('\0', '')

    # Remove leading/trailing whitespace and dots
    filename = filename.strip('. ')

    # Replace any non-alphanumeric characters (except . - _) with underscores
    filename = re.sub(r'[^\w\.\-]', '_', filename)

    # Prevent multiple consecutive dots (e.g., ..)
    filename = re.sub(r'\.{2,}', '.', filename)

    # Limit filename length (255 is typical filesystem limit, use 200 to be safe)
    if len(filename) > 200:
        name, ext = os.path.splitext(filename)
        filename = name[:200-len(ext)] + ext

    if not filename or filename == '.' or filename == '..':
        raise FileValidationError("Invalid filename")

    return filename


def validate_file_size(file_data):
    """Validate file size is within limits.

    Args:
        file_data: Binary file data (bytes)

    Raises:
        FileValidationError: If file is too large
    """
    file_size = len(file_data)
    if file_size > MAX_FILE_SIZE:
        raise FileValidationError(
            f"File size ({file_size / 1024 / 1024:.2f} MB) exceeds maximum "
            f"allowed size ({MAX_FILE_SIZE / 1024 / 1024:.2f} MB)"
        )

    if file_size == 0:
        raise FileValidationError("File is empty")


def validate_image_dimensions(image):
    """Validate image dimensions are reasonable.

    Args:
        image: PIL Image object

    Raises:
        FileValidationError: If dimensions are invalid
    """
    width, height = image.size

    if width > MAX_IMAGE_DIMENSION or height > MAX_IMAGE_DIMENSION:
        raise FileValidationError(
            f"Image dimensions ({width}x{height}) exceed maximum "
            f"allowed dimensions ({MAX_IMAGE_DIMENSION}x{MAX_IMAGE_DIMENSION})"
        )

    if width < 1 or height < 1:
        raise FileValidationError("Image dimensions are invalid")


def generate_unique_id():
    """Generate a unique 8-character ID for photos.

    Returns:
        str: Unique 8-character alphanumeric ID
    """
    # Use secrets for cryptographically secure random generation
    # Generate 6 random bytes and convert to hex (12 chars), then take first 8
    return secrets.token_hex(4).upper()


def get_save_options(mime_type, is_thumbnail=False):
    """Get format-specific save options for PIL Image.save().

    Different image formats support different save parameters. This function
    returns the appropriate options for each format to ensure reliable encoding.

    Args:
        mime_type: MIME type of the image (e.g., 'image/jpeg', 'image/png')
        is_thumbnail: If True, use thumbnail-appropriate compression settings

    Returns:
        dict: Save options to pass to PIL Image.save() as **kwargs
    """
    if mime_type == 'image/jpeg':
        # JPEG supports quality (1-100) and optimization
        return {
            'quality': 85 if is_thumbnail else 95,
            'optimize': True,
            'progressive': True,  # Progressive JPEG for better web performance
        }
    elif mime_type == 'image/png':
        # PNG is lossless; no quality param, but supports compression level
        return {
            'optimize': True,
            'compress_level': 9 if is_thumbnail else 6,  # 0-9, higher = smaller but slower
        }
    elif mime_type == 'image/webp':
        # WebP supports quality (0-100, different scale than JPEG)
        return {
            'quality': 80 if is_thumbnail else 90,
            'method': 6,  # 0-6, higher = better compression but slower
        }
    elif mime_type == 'image/avif':
        # AVIF supports quality (0-100)
        return {
            'quality': 70 if is_thumbnail else 80,  # AVIF has excellent compression
        }
    else:
        # Fallback for unknown types (shouldn't happen due to validation)
        return {'optimize': True}


def generate_thumbnail(image, thumbnail_path, mime_type):
    """Generate a thumbnail from an image.

    Args:
        image: PIL Image object
        thumbnail_path: Path to save the thumbnail
        mime_type: MIME type of the image (for format-specific save options)

    Returns:
        tuple: (thumbnail_width, thumbnail_height)
    """
    # Create a copy to avoid modifying the original
    thumbnail = image.copy()

    # Use LANCZOS resampling for high-quality thumbnails
    thumbnail.thumbnail(THUMBNAIL_SIZE, Image.Resampling.LANCZOS)

    # Convert RGBA to RGB if saving as JPEG (JPEG doesn't support transparency)
    if thumbnail.mode == 'RGBA' and mime_type == 'image/jpeg':
        # Create white background
        background = Image.new('RGB', thumbnail.size, (255, 255, 255))
        background.paste(thumbnail, mask=thumbnail.split()[3])  # Use alpha channel as mask
        thumbnail = background

    # Get format-specific save options
    save_options = get_save_options(mime_type, is_thumbnail=True)

    # Save thumbnail with format-appropriate options
    thumbnail.save(thumbnail_path, **save_options)

    return thumbnail.size


def process_upload(file_data, original_filename):
    """Process an uploaded file with full security validation.

    This function:
    1. Validates file size
    2. Validates magic bytes (actual file type)
    3. Sanitizes filename
    4. Opens and validates image
    5. Re-encodes image (strips metadata, prevents exploits)
    6. Generates thumbnail
    7. Saves both files

    Args:
        file_data: Binary file data (bytes)
        original_filename: Original filename from upload

    Returns:
        dict: {
            'photo_id': str,
            'filename': str,
            'file_path': str,
            'thumbnail_path': str,
            'file_size': int,
            'mime_type': str,
            'width': int,
            'height': int
        }

    Raises:
        FileValidationError: If validation fails
    """
    # Validate file size
    validate_file_size(file_data)

    # Validate magic bytes and get MIME type
    mime_type = validate_magic_bytes(file_data)

    # Sanitize filename
    safe_filename = sanitize_filename(original_filename)

    # Open image with PIL for validation and processing
    try:
        image = Image.open(io.BytesIO(file_data))
        image.verify()  # Verify it's a valid image

        # Reopen after verify (verify() closes the file)
        image = Image.open(io.BytesIO(file_data))
    except Exception as e:
        raise FileValidationError(f"Invalid or corrupted image file: {str(e)}")

    # Validate dimensions
    validate_image_dimensions(image)

    # Generate unique photo ID
    photo_id = generate_unique_id()

    # Get file extension from MIME type
    extension = MIME_TO_EXTENSION.get(mime_type, '.jpg')

    # Generate unique filenames
    unique_filename = f"{photo_id}_{safe_filename}"
    if not unique_filename.endswith(extension):
        # Ensure correct extension
        base_name = os.path.splitext(unique_filename)[0]
        unique_filename = f"{base_name}{extension}"

    # Create full paths
    artwork_path = os.path.join(ARTWORKS_DIR, unique_filename)
    thumbnail_filename = f"thumb_{unique_filename}"
    thumbnail_path = os.path.join(THUMBNAILS_DIR, thumbnail_filename)

    # Ensure upload directories exist
    os.makedirs(ARTWORKS_DIR, exist_ok=True)
    os.makedirs(THUMBNAILS_DIR, exist_ok=True)

    # Re-encode the image (strips EXIF and other metadata, prevents exploits)
    try:
        # Convert RGBA to RGB if saving as JPEG (JPEG doesn't support transparency)
        if image.mode == 'RGBA' and mime_type == 'image/jpeg':
            background = Image.new('RGB', image.size, (255, 255, 255))
            background.paste(image, mask=image.split()[3])
            image = background

        # Get format-specific save options
        save_options = get_save_options(mime_type, is_thumbnail=False)

        # Save re-encoded image with format-appropriate options
        image.save(artwork_path, **save_options)

        # Generate thumbnail
        thumbnail_size = generate_thumbnail(image, thumbnail_path, mime_type)

        # Get actual file size after re-encoding
        actual_file_size = os.path.getsize(artwork_path)

    except Exception as e:
        # Clean up any created files on error
        if os.path.exists(artwork_path):
            os.remove(artwork_path)
        if os.path.exists(thumbnail_path):
            os.remove(thumbnail_path)
        raise FileValidationError(f"Failed to process image: {str(e)}")

    # Return metadata
    return {
        'photo_id': photo_id,
        'filename': safe_filename,
        'file_path': f"uploads/artworks/{unique_filename}",
        'thumbnail_path': f"uploads/thumbnails/{thumbnail_filename}",
        'file_size': actual_file_size,
        'mime_type': mime_type,
        'width': image.width,
        'height': image.height
    }


def delete_photo_files(file_path, thumbnail_path):
    """Delete photo and thumbnail files from filesystem.

    Args:
        file_path: Relative path to the photo file
        thumbnail_path: Relative path to the thumbnail file

    Returns:
        tuple: (photo_deleted, thumbnail_deleted) boolean flags
    """
    base_dir = os.path.dirname(__file__)
    photo_deleted = False
    thumbnail_deleted = False

    # Delete main photo
    try:
        full_path = os.path.join(base_dir, file_path)
        if os.path.exists(full_path):
            os.remove(full_path)
            photo_deleted = True
    except Exception:
        pass

    # Delete thumbnail
    try:
        full_thumb_path = os.path.join(base_dir, thumbnail_path)
        if os.path.exists(full_thumb_path):
            os.remove(full_thumb_path)
            thumbnail_deleted = True
    except Exception:
        pass

    return photo_deleted, thumbnail_deleted


