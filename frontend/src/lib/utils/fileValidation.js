export const MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB
export const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/avif'];

/**
 * Validate an uploaded image file matches our constraints.
 * @param {File} file
 * @returns {{valid: boolean, error?: string}}
 */
export function validateImageFile(file) {
  if (!file) {
    return { valid: false, error: 'No file selected.' };
  }

  if (!file.type || !ALLOWED_IMAGE_TYPES.includes(file.type)) {
    return {
      valid: false,
      error: `"${file.name}" is not a supported image format. Accepted formats: JPG, PNG, WebP, AVIF.`
    };
  }

  if (file.size > MAX_IMAGE_SIZE_BYTES) {
    const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
    return {
      valid: false,
      error: `"${file.name}" is too large (${sizeMB}MB). Maximum file size is 10MB.`
    };
  }

  if (file.size === 0) {
    return {
      valid: false,
      error: `"${file.name}" is empty. Please choose another file.`
    };
  }

  return { valid: true };
}
