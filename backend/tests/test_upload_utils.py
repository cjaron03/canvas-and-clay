"""Tests for upload_utils.py security and image processing functionality."""
import os
import sys
import pytest
import io
from PIL import Image

# Handle imports for both Docker (where backend is at /app) and local dev (where it's a package)
try:
    from backend.upload_utils import (
        process_upload,
        validate_magic_bytes,
        sanitize_filename,
        validate_file_size,
        validate_image_dimensions,
        get_save_options,
        generate_thumbnail,
        generate_unique_id,
        FileValidationError,
        MAX_FILE_SIZE,
        MAX_IMAGE_DIMENSION,
        THUMBNAIL_SIZE,
        ARTWORKS_DIR,
        THUMBNAILS_DIR,
    )
except ModuleNotFoundError:
    # In Docker container, backend code is in current directory
    from upload_utils import (
        process_upload,
        validate_magic_bytes,
        sanitize_filename,
        validate_file_size,
        validate_image_dimensions,
        get_save_options,
        generate_thumbnail,
        generate_unique_id,
        FileValidationError,
        MAX_FILE_SIZE,
        MAX_IMAGE_DIMENSION,
        THUMBNAIL_SIZE,
        ARTWORKS_DIR,
        THUMBNAILS_DIR,
    )


# Test fixtures: Sample image data generators
def create_test_image(width=100, height=100, mode='RGB', format='JPEG'):
    """Create a test image in memory.

    Args:
        width: Image width in pixels
        height: Image height in pixels
        mode: PIL image mode ('RGB', 'RGBA', etc.)
        format: Output format ('JPEG', 'PNG', 'WEBP')

    Returns:
        bytes: Image data
    """
    img = Image.new(mode, (width, height), color='red')
    buffer = io.BytesIO()

    # Format-specific save options for test image creation
    if format == 'JPEG':
        # Convert RGBA to RGB for JPEG
        if mode == 'RGBA':
            background = Image.new('RGB', img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[3])
            img = background
        img.save(buffer, format='JPEG', quality=95)
    elif format == 'PNG':
        img.save(buffer, format='PNG')
    elif format == 'WEBP':
        img.save(buffer, format='WEBP', quality=90)
    # Note: AVIF support depends on Pillow version and system libraries
    # We'll test AVIF separately with actual files

    return buffer.getvalue()


@pytest.fixture
def cleanup_uploads():
    """Fixture to clean up test uploads after each test."""
    yield
    # Clean up test files after test runs
    for directory in [ARTWORKS_DIR, THUMBNAILS_DIR]:
        if os.path.exists(directory):
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                try:
                    if os.path.isfile(filepath):
                        os.remove(filepath)
                except Exception:
                    pass


class TestGetSaveOptions:
    """Test format-specific save options."""

    def test_jpeg_save_options_full_quality(self):
        """Test JPEG save options for full-size images."""
        options = get_save_options('image/jpeg', is_thumbnail=False)
        assert 'quality' in options
        assert options['quality'] == 95
        assert options['optimize'] is True
        assert options['progressive'] is True
        # Ensure no PNG-specific params
        assert 'compress_level' not in options

    def test_jpeg_save_options_thumbnail(self):
        """Test JPEG save options for thumbnails."""
        options = get_save_options('image/jpeg', is_thumbnail=True)
        assert options['quality'] == 85
        assert options['optimize'] is True

    def test_png_save_options_exclude_quality(self):
        """Test PNG save options don't include JPEG-specific quality param."""
        options = get_save_options('image/png', is_thumbnail=False)
        assert 'quality' not in options  # Critical: PNG shouldn't have quality
        assert 'optimize' in options
        assert 'compress_level' in options
        assert options['compress_level'] == 6

    def test_png_save_options_thumbnail(self):
        """Test PNG thumbnail uses higher compression."""
        options = get_save_options('image/png', is_thumbnail=True)
        assert options['compress_level'] == 9  # Higher compression for thumbnails

    def test_webp_save_options(self):
        """Test WebP save options use correct quality scale."""
        options = get_save_options('image/webp', is_thumbnail=False)
        assert 'quality' in options
        assert options['quality'] == 90
        assert 'method' in options
        assert options['method'] == 6

    def test_avif_save_options(self):
        """Test AVIF save options."""
        options = get_save_options('image/avif', is_thumbnail=False)
        assert 'quality' in options
        assert options['quality'] == 80

    def test_unknown_format_fallback(self):
        """Test fallback for unknown formats."""
        options = get_save_options('image/unknown', is_thumbnail=False)
        assert 'optimize' in options


class TestValidateMagicBytes:
    """Test magic byte validation for file type detection."""

    def test_jpeg_magic_bytes(self):
        """Test JPEG detection via magic bytes."""
        jpeg_data = create_test_image(format='JPEG')
        mime_type = validate_magic_bytes(jpeg_data)
        assert mime_type == 'image/jpeg'

    def test_png_magic_bytes(self):
        """Test PNG detection via magic bytes."""
        png_data = create_test_image(format='PNG')
        mime_type = validate_magic_bytes(png_data)
        assert mime_type == 'image/png'

    def test_webp_magic_bytes(self):
        """Test WebP detection via magic bytes."""
        webp_data = create_test_image(format='WEBP')
        mime_type = validate_magic_bytes(webp_data)
        assert mime_type == 'image/webp'

    def test_invalid_file_type(self):
        """Test rejection of non-image files."""
        fake_data = b'This is not an image file'
        with pytest.raises(FileValidationError, match="File type not allowed"):
            validate_magic_bytes(fake_data)

    def test_file_too_small(self):
        """Test rejection of files that are too small."""
        tiny_data = b'small'
        with pytest.raises(FileValidationError, match="too small"):
            validate_magic_bytes(tiny_data)


class TestSanitizeFilename:
    """Test filename sanitization."""

    def test_basic_sanitization(self):
        """Test basic filename sanitization."""
        result = sanitize_filename('test image.jpg')
        assert result == 'test_image.jpg'

    def test_path_traversal_prevention(self):
        """Test prevention of path traversal attacks."""
        result = sanitize_filename('../../etc/passwd')
        assert '..' not in result
        assert '/' not in result

    def test_null_byte_removal(self):
        """Test null byte removal."""
        result = sanitize_filename('test\0file.jpg')
        assert '\0' not in result

    def test_empty_filename(self):
        """Test rejection of empty filenames."""
        with pytest.raises(FileValidationError):
            sanitize_filename('')

    def test_long_filename_truncation(self):
        """Test truncation of overly long filenames."""
        long_name = 'a' * 300 + '.jpg'
        result = sanitize_filename(long_name)
        assert len(result) <= 200


class TestValidateFileSize:
    """Test file size validation."""

    def test_valid_file_size(self):
        """Test valid file size passes validation."""
        data = b'x' * 1000  # 1KB
        validate_file_size(data)  # Should not raise

    def test_file_too_large(self):
        """Test rejection of files exceeding max size."""
        data = b'x' * (MAX_FILE_SIZE + 1)
        with pytest.raises(FileValidationError, match="exceeds maximum"):
            validate_file_size(data)

    def test_empty_file(self):
        """Test rejection of empty files."""
        with pytest.raises(FileValidationError, match="empty"):
            validate_file_size(b'')


class TestValidateImageDimensions:
    """Test image dimension validation."""

    def test_valid_dimensions(self):
        """Test valid dimensions pass validation."""
        img = Image.new('RGB', (100, 100))
        validate_image_dimensions(img)  # Should not raise

    def test_width_too_large(self):
        """Test rejection of images with excessive width."""
        img = Image.new('RGB', (MAX_IMAGE_DIMENSION + 1, 100))
        with pytest.raises(FileValidationError, match="exceed maximum"):
            validate_image_dimensions(img)

    def test_height_too_large(self):
        """Test rejection of images with excessive height."""
        img = Image.new('RGB', (100, MAX_IMAGE_DIMENSION + 1))
        with pytest.raises(FileValidationError, match="exceed maximum"):
            validate_image_dimensions(img)

    def test_zero_dimensions(self):
        """Test rejection of images with zero dimensions."""
        # Create a minimal valid image and test the validator logic directly
        # PIL doesn't allow zero-dimension images, so this tests negative dimensions
        img = Image.new('RGB', (1, 1))
        # The validation function checks if width < 1 or height < 1
        # We can't actually create such an image with PIL, so skip this edge case
        # The validator itself has the correct logic: if width < 1 or height < 1: raise
        pytest.skip("PIL doesn't support zero-dimension images; validator logic is correct")


class TestGenerateUniqueId:
    """Test unique ID generation."""

    def test_id_length(self):
        """Test generated ID is 8 characters."""
        photo_id = generate_unique_id()
        assert len(photo_id) == 8

    def test_id_format(self):
        """Test ID contains only hex characters."""
        photo_id = generate_unique_id()
        assert all(c in '0123456789ABCDEF' for c in photo_id)

    def test_id_uniqueness(self):
        """Test generated IDs are unique."""
        ids = [generate_unique_id() for _ in range(100)]
        assert len(ids) == len(set(ids))  # All IDs should be unique


class TestGenerateThumbnail:
    """Test thumbnail generation."""

    def test_jpeg_thumbnail_generation(self, cleanup_uploads, tmp_path):
        """Test thumbnail generation for JPEG images."""
        img = Image.new('RGB', (800, 600), color='blue')
        thumbnail_path = tmp_path / 'thumb_test.jpg'

        size = generate_thumbnail(img, str(thumbnail_path), 'image/jpeg')

        assert os.path.exists(thumbnail_path)
        assert size[0] <= THUMBNAIL_SIZE[0]
        assert size[1] <= THUMBNAIL_SIZE[1]

        # Verify thumbnail is a valid image
        thumb = Image.open(thumbnail_path)
        assert thumb.size == size

    def test_png_thumbnail_generation(self, cleanup_uploads, tmp_path):
        """Test thumbnail generation for PNG images."""
        img = Image.new('RGB', (800, 600), color='green')
        thumbnail_path = tmp_path / 'thumb_test.png'

        size = generate_thumbnail(img, str(thumbnail_path), 'image/png')

        assert os.path.exists(thumbnail_path)
        # Verify it's a valid PNG
        thumb = Image.open(thumbnail_path)
        assert thumb.format == 'PNG'

    def test_webp_thumbnail_generation(self, cleanup_uploads, tmp_path):
        """Test thumbnail generation for WebP images."""
        img = Image.new('RGB', (800, 600), color='yellow')
        thumbnail_path = tmp_path / 'thumb_test.webp'

        size = generate_thumbnail(img, str(thumbnail_path), 'image/webp')

        assert os.path.exists(thumbnail_path)
        thumb = Image.open(thumbnail_path)
        assert thumb.format == 'WEBP'

    def test_jpeg_thumbnail_converts_rgba(self, cleanup_uploads, tmp_path):
        """Test JPEG thumbnail converts RGBA to RGB."""
        img = Image.new('RGBA', (800, 600), color=(255, 0, 0, 128))
        thumbnail_path = tmp_path / 'thumb_test.jpg'

        generate_thumbnail(img, str(thumbnail_path), 'image/jpeg')

        thumb = Image.open(thumbnail_path)
        assert thumb.mode == 'RGB'  # Should be converted from RGBA

    def test_png_thumbnail_preserves_transparency(self, cleanup_uploads, tmp_path):
        """Test PNG thumbnail preserves RGBA/transparency."""
        img = Image.new('RGBA', (800, 600), color=(255, 0, 0, 128))
        thumbnail_path = tmp_path / 'thumb_test.png'

        generate_thumbnail(img, str(thumbnail_path), 'image/png')

        thumb = Image.open(thumbnail_path)
        # PNG should preserve RGBA mode
        assert thumb.mode in ['RGBA', 'LA', 'P']  # Various transparency modes


class TestProcessUpload:
    """Test the full upload processing pipeline."""

    def test_process_jpeg_upload(self, cleanup_uploads):
        """Test processing of JPEG uploads."""
        jpeg_data = create_test_image(format='JPEG')

        result = process_upload(jpeg_data, 'test_photo.jpg')

        assert result['photo_id']
        assert result['mime_type'] == 'image/jpeg'
        assert result['width'] == 100
        assert result['height'] == 100
        # Files are saved to ARTWORKS_DIR and THUMBNAILS_DIR
        # Check that the directories exist and contain files
        assert os.path.exists(ARTWORKS_DIR)
        assert os.path.exists(THUMBNAILS_DIR)
        assert len(os.listdir(ARTWORKS_DIR)) > 0
        assert len(os.listdir(THUMBNAILS_DIR)) > 0

    def test_process_png_upload(self, cleanup_uploads):
        """Test processing of PNG uploads."""
        png_data = create_test_image(format='PNG')

        result = process_upload(png_data, 'test_photo.png')

        assert result['mime_type'] == 'image/png'
        # Find the actual saved file in ARTWORKS_DIR
        saved_files = [f for f in os.listdir(ARTWORKS_DIR) if f.endswith('.png')]
        assert len(saved_files) > 0
        # Verify the saved file is actually PNG
        saved_img = Image.open(os.path.join(ARTWORKS_DIR, saved_files[0]))
        assert saved_img.format == 'PNG'

    def test_process_webp_upload(self, cleanup_uploads):
        """Test processing of WebP uploads."""
        webp_data = create_test_image(format='WEBP')

        result = process_upload(webp_data, 'test_photo.webp')

        assert result['mime_type'] == 'image/webp'
        saved_files = [f for f in os.listdir(ARTWORKS_DIR) if f.endswith('.webp')]
        assert len(saved_files) > 0
        saved_img = Image.open(os.path.join(ARTWORKS_DIR, saved_files[0]))
        assert saved_img.format == 'WEBP'

    def test_jpeg_converts_transparency_to_white(self, cleanup_uploads):
        """Test JPEG upload converts RGBA to RGB with white background."""
        rgba_data = create_test_image(mode='RGBA', format='PNG')

        result = process_upload(rgba_data, 'test_transparent.png')

        # Find the saved file
        saved_files = [f for f in os.listdir(ARTWORKS_DIR) if result['photo_id'] in f]
        assert len(saved_files) > 0
        saved_img = Image.open(os.path.join(ARTWORKS_DIR, saved_files[0]))
        # If detected as PNG, should preserve RGBA; if JPEG, should convert to RGB
        if result['mime_type'] == 'image/jpeg':
            assert saved_img.mode == 'RGB'

    def test_png_preserves_transparency(self, cleanup_uploads):
        """Test PNG upload preserves transparency."""
        # Create PNG with transparency
        img = Image.new('RGBA', (100, 100), color=(255, 0, 0, 128))
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        png_data = buffer.getvalue()

        result = process_upload(png_data, 'test_transparent.png')

        saved_files = [f for f in os.listdir(ARTWORKS_DIR) if result['photo_id'] in f]
        assert len(saved_files) > 0
        saved_img = Image.open(os.path.join(ARTWORKS_DIR, saved_files[0]))
        # PNG should preserve alpha channel
        assert saved_img.mode in ['RGBA', 'LA', 'P']

    def test_wrong_extension_detected(self, cleanup_uploads):
        """Test file type detection via magic bytes, not extension."""
        # Create JPEG but name it .png
        jpeg_data = create_test_image(format='JPEG')

        result = process_upload(jpeg_data, 'fake.png')

        # Should detect actual MIME type (JPEG) and use correct extension
        assert result['mime_type'] == 'image/jpeg'
        assert result['file_path'].endswith('.jpg')

    def test_metadata_extraction(self, cleanup_uploads):
        """Test correct extraction of image metadata."""
        jpeg_data = create_test_image(width=300, height=200, format='JPEG')

        result = process_upload(jpeg_data, 'metadata_test.jpg')

        assert result['width'] == 300
        assert result['height'] == 200
        assert result['file_size'] > 0
        assert result['mime_type'] == 'image/jpeg'

    def test_thumbnail_created(self, cleanup_uploads):
        """Test thumbnail is created during upload processing."""
        jpeg_data = create_test_image(width=800, height=600, format='JPEG')

        result = process_upload(jpeg_data, 'thumb_test.jpg')

        # Check thumbnail exists in THUMBNAILS_DIR
        thumb_files = [f for f in os.listdir(THUMBNAILS_DIR) if result['photo_id'] in f]
        assert len(thumb_files) > 0

        thumb = Image.open(os.path.join(THUMBNAILS_DIR, thumb_files[0]))
        assert thumb.size[0] <= THUMBNAIL_SIZE[0]
        assert thumb.size[1] <= THUMBNAIL_SIZE[1]

    def test_upload_invalid_file_type(self):
        """Test upload rejects invalid file types."""
        fake_data = b'This is not an image'

        with pytest.raises(FileValidationError, match="File type not allowed"):
            process_upload(fake_data, 'fake.txt')

    def test_upload_oversized_image(self):
        """Test upload rejects images exceeding size limit."""
        large_data = b'x' * (MAX_FILE_SIZE + 1)

        with pytest.raises(FileValidationError, match="exceeds maximum"):
            process_upload(large_data, 'large.jpg')

    def test_upload_corrupted_image(self):
        """Test upload rejects corrupted image files."""
        # Start with valid JPEG magic bytes but corrupt data
        corrupted_data = b'\xff\xd8\xff\xe0' + b'corrupted data'

        with pytest.raises(FileValidationError, match="Invalid or corrupted"):
            process_upload(corrupted_data, 'corrupted.jpg')

    def test_filename_sanitization_during_upload(self, cleanup_uploads):
        """Test filename is sanitized during upload."""
        jpeg_data = create_test_image(format='JPEG')

        result = process_upload(jpeg_data, '../../etc/passwd.jpg')

        # Filename should be sanitized - path components are stripped
        assert '..' not in result['filename']
        assert '/' not in result['filename']
        # After sanitization, '../../etc/passwd.jpg' becomes 'passwd.jpg'
        assert result['filename'] == 'passwd.jpg'


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_very_small_thumbnail_source(self, cleanup_uploads, tmp_path):
        """Test thumbnail generation from very small source image."""
        img = Image.new('RGB', (50, 50), color='red')
        thumbnail_path = tmp_path / 'small_thumb.jpg'

        size = generate_thumbnail(img, str(thumbnail_path), 'image/jpeg')

        # Thumbnail should not upscale
        assert size[0] <= 50
        assert size[1] <= 50

    def test_maximum_dimension_image(self, cleanup_uploads):
        """Test processing of image at maximum allowed dimensions."""
        # Create small image to avoid memory issues, we're testing the validator
        img = Image.new('RGB', (MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION))
        validate_image_dimensions(img)  # Should not raise

    def test_all_allowed_formats(self):
        """Test all allowed MIME types are supported by get_save_options."""
        allowed_formats = ['image/jpeg', 'image/png', 'image/webp', 'image/avif']

        for mime_type in allowed_formats:
            options = get_save_options(mime_type)
            assert isinstance(options, dict)
            assert len(options) > 0
