"""Security utilities for file upload handling.

This module provides comprehensive file upload validation including:
- Magic byte validation (actual file type detection)
- Filename sanitization (path traversal prevention)
- File size validation
- Image dimension validation
- Thumbnail generation
- Disk space monitoring (exhaustion protection)
"""
import os
import re
import io
import secrets
import shutil
from PIL import Image
import magic


# Configuration
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB in bytes

# Disk space protection thresholds
MIN_DISK_FREE_PERCENT = 10  # Reject uploads when disk is < 10% free
MIN_DISK_FREE_BYTES = 100 * 1024 * 1024  # Minimum 100MB free regardless of percentage
MAX_IMAGE_DIMENSION = 8000  # Maximum width or height in pixels
THUMBNAIL_SIZE = (200, 200)  # Thumbnail dimensions
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
ARTWORKS_DIR = os.path.join(UPLOAD_DIR, 'artworks')
THUMBNAILS_DIR = os.path.join(UPLOAD_DIR, 'thumbnails')
ARTIST_PROFILE_DIR = os.path.join(UPLOAD_DIR, 'artist_profiles')
ARTIST_PROFILE_THUMBNAILS_DIR = os.path.join(UPLOAD_DIR, 'artist_profile_thumbnails')
ARTIST_PROFILE_THUMBNAIL_SIZE = (200, 200)

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


class DiskSpaceError(Exception):
    """Raised when disk space is critically low."""
    pass


class QuotaExceededError(Exception):
    """Raised when user's upload quota would be exceeded."""
    pass


def get_disk_usage(path=None):
    """Get disk usage statistics for the upload directory.

    Args:
        path: Directory to check (defaults to UPLOAD_DIR)

    Returns:
        dict: {
            'total': Total disk space in bytes,
            'used': Used space in bytes,
            'free': Free space in bytes,
            'free_percent': Percentage of disk that is free
        }
    """
    check_path = path or UPLOAD_DIR
    # Ensure directory exists
    os.makedirs(check_path, exist_ok=True)

    usage = shutil.disk_usage(check_path)
    free_percent = (usage.free / usage.total) * 100 if usage.total > 0 else 0

    return {
        'total': usage.total,
        'used': usage.used,
        'free': usage.free,
        'free_percent': free_percent
    }


def check_disk_space(required_bytes=0):
    """Check if there's sufficient disk space for an upload.

    Args:
        required_bytes: Additional bytes needed for the upload

    Returns:
        tuple: (ok: bool, message: str, disk_info: dict)

    Raises:
        DiskSpaceError: If disk space is critically low
    """
    disk_info = get_disk_usage()

    # Check minimum percentage threshold
    if disk_info['free_percent'] < MIN_DISK_FREE_PERCENT:
        return (
            False,
            f"Disk space critically low ({disk_info['free_percent']:.1f}% free). "
            f"Uploads temporarily disabled.",
            disk_info
        )

    # Check minimum absolute free space
    if disk_info['free'] < MIN_DISK_FREE_BYTES:
        return (
            False,
            f"Disk space critically low ({disk_info['free'] // (1024*1024)}MB free). "
            f"Uploads temporarily disabled.",
            disk_info
        )

    # Check if upload would push us below threshold
    if disk_info['free'] - required_bytes < MIN_DISK_FREE_BYTES:
        return (
            False,
            f"Upload would exceed available disk space. "
            f"Only {disk_info['free'] // (1024*1024)}MB free.",
            disk_info
        )

    return (True, "OK", disk_info)


def validate_upload_quota(user, file_size_bytes):
    """Validate that upload won't exceed user's quota.

    Args:
        user: User object with quota tracking
        file_size_bytes: Size of file to upload

    Returns:
        tuple: (ok: bool, message: str)

    Raises:
        QuotaExceededError: If upload would exceed quota
    """
    # Admins have unlimited quota
    if hasattr(user, 'is_admin') and user.is_admin:
        return (True, "OK")

    # Check if user has quota attributes (backwards compatibility)
    if not hasattr(user, 'upload_quota_bytes') or not hasattr(user, 'bytes_uploaded'):
        return (True, "OK")  # No quota tracking, allow upload

    quota = user.upload_quota_bytes or 0
    used = user.bytes_uploaded or 0

    if used + file_size_bytes > quota:
        remaining = max(0, quota - used)
        return (
            False,
            f"Upload would exceed your quota. "
            f"Remaining: {remaining // (1024*1024)}MB, "
            f"File size: {file_size_bytes // (1024*1024)}MB"
        )

    return (True, "OK")


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


def generate_thumbnail(image, thumbnail_path, mime_type, size=THUMBNAIL_SIZE):
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
    thumbnail.thumbnail(size, Image.Resampling.LANCZOS)

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


def process_upload(
    file_data,
    original_filename,
    output_dir=None,
    thumbnail_dir=None,
    thumbnail_size=None,
    filename_prefix=''
):
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

    output_dir = output_dir or ARTWORKS_DIR
    thumbnail_dir = thumbnail_dir or THUMBNAILS_DIR
    thumbnail_size = thumbnail_size or THUMBNAIL_SIZE

    # Generate unique photo ID
    photo_id = generate_unique_id()

    # Get file extension from MIME type
    extension = MIME_TO_EXTENSION.get(mime_type, '.jpg')

    # Apply optional filename prefix before unique suffix for easier tracing
    base_filename = safe_filename
    if filename_prefix:
        name, ext = os.path.splitext(safe_filename)
        base_filename = f"{filename_prefix}_{name}{ext}"

    # Generate unique filenames
    unique_filename = f"{photo_id}_{base_filename}"
    if not unique_filename.endswith(extension):
        # Ensure correct extension
        base_name = os.path.splitext(unique_filename)[0]
        unique_filename = f"{base_name}{extension}"

    # Create full paths
    artwork_path = os.path.join(output_dir, unique_filename)
    thumbnail_filename = f"thumb_{unique_filename}"
    thumbnail_path = os.path.join(thumbnail_dir, thumbnail_filename)

    # Ensure upload directories exist
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(thumbnail_dir, exist_ok=True)

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
        generate_thumbnail(image, thumbnail_path, mime_type, size=thumbnail_size)

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
    base_dir = os.path.dirname(__file__)
    file_path_relative = os.path.relpath(artwork_path, base_dir)
    thumbnail_path_relative = os.path.relpath(thumbnail_path, base_dir)

    return {
        'photo_id': photo_id,
        'filename': safe_filename,
        'file_path': file_path_relative.replace('\\', '/'),
        'thumbnail_path': thumbnail_path_relative.replace('\\', '/'),
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


def process_artist_profile_upload(file_data, original_filename, artist_id):
    """Process an artist profile photo upload and store it in dedicated directories."""
    prefix = f"{artist_id}_profile"
    return process_upload(
        file_data,
        original_filename,
        output_dir=ARTIST_PROFILE_DIR,
        thumbnail_dir=ARTIST_PROFILE_THUMBNAILS_DIR,
        thumbnail_size=ARTIST_PROFILE_THUMBNAIL_SIZE,
        filename_prefix=prefix
    )
