import { describe, it, expect } from 'vitest';
import {
	validateImageFile,
	MAX_IMAGE_SIZE_BYTES,
	ALLOWED_IMAGE_TYPES
} from './fileValidation.js';

describe('fileValidation constants', () => {
	it('MAX_IMAGE_SIZE_BYTES should be 10MB', () => {
		expect(MAX_IMAGE_SIZE_BYTES).toBe(10 * 1024 * 1024);
	});

	it('ALLOWED_IMAGE_TYPES should include JPEG, PNG, WebP, AVIF', () => {
		expect(ALLOWED_IMAGE_TYPES).toContain('image/jpeg');
		expect(ALLOWED_IMAGE_TYPES).toContain('image/png');
		expect(ALLOWED_IMAGE_TYPES).toContain('image/webp');
		expect(ALLOWED_IMAGE_TYPES).toContain('image/avif');
		expect(ALLOWED_IMAGE_TYPES).toHaveLength(4);
	});
});

describe('validateImageFile', () => {
	// Helper to create mock File objects
	const createMockFile = (name, size, type) => ({
		name,
		size,
		type
	});

	describe('null/undefined handling', () => {
		it('should reject null file', () => {
			const result = validateImageFile(null);
			expect(result.valid).toBe(false);
			expect(result.error).toBe('No file selected.');
		});

		it('should reject undefined file', () => {
			const result = validateImageFile(undefined);
			expect(result.valid).toBe(false);
			expect(result.error).toBe('No file selected.');
		});
	});

	describe('MIME type validation', () => {
		it('should accept image/jpeg', () => {
			const file = createMockFile('test.jpg', 1024, 'image/jpeg');
			const result = validateImageFile(file);
			expect(result.valid).toBe(true);
			expect(result.error).toBeUndefined();
		});

		it('should accept image/png', () => {
			const file = createMockFile('test.png', 1024, 'image/png');
			const result = validateImageFile(file);
			expect(result.valid).toBe(true);
		});

		it('should accept image/webp', () => {
			const file = createMockFile('test.webp', 1024, 'image/webp');
			const result = validateImageFile(file);
			expect(result.valid).toBe(true);
		});

		it('should accept image/avif', () => {
			const file = createMockFile('test.avif', 1024, 'image/avif');
			const result = validateImageFile(file);
			expect(result.valid).toBe(true);
		});

		it('should reject image/gif', () => {
			const file = createMockFile('test.gif', 1024, 'image/gif');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('not a supported image format');
			expect(result.error).toContain('test.gif');
		});

		it('should reject application/pdf', () => {
			const file = createMockFile('document.pdf', 1024, 'application/pdf');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('not a supported image format');
		});

		it('should reject file with empty type', () => {
			const file = createMockFile('unknown', 1024, '');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
		});

		it('should reject file with null type', () => {
			const file = createMockFile('unknown', 1024, null);
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
		});
	});

	describe('file size validation', () => {
		it('should accept file under 10MB', () => {
			const file = createMockFile('small.jpg', 5 * 1024 * 1024, 'image/jpeg');
			const result = validateImageFile(file);
			expect(result.valid).toBe(true);
		});

		it('should accept file exactly at 10MB', () => {
			const file = createMockFile('exact.jpg', MAX_IMAGE_SIZE_BYTES, 'image/jpeg');
			const result = validateImageFile(file);
			expect(result.valid).toBe(true);
		});

		it('should reject file over 10MB', () => {
			const file = createMockFile('large.jpg', MAX_IMAGE_SIZE_BYTES + 1, 'image/jpeg');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('too large');
			expect(result.error).toContain('large.jpg');
			expect(result.error).toContain('Maximum file size is 10MB');
		});

		it('should show file size in MB in error message', () => {
			const file = createMockFile('huge.jpg', 15 * 1024 * 1024, 'image/jpeg');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('15.00MB');
		});
	});

	describe('empty file validation', () => {
		it('should reject file with size 0', () => {
			const file = createMockFile('empty.jpg', 0, 'image/jpeg');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('empty');
			expect(result.error).toContain('empty.jpg');
		});
	});

	describe('validation order', () => {
		// Type is checked before size
		it('should report type error before size error for invalid type + oversized', () => {
			const file = createMockFile('bad.gif', MAX_IMAGE_SIZE_BYTES + 1000, 'image/gif');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('not a supported image format');
		});

		// Size is checked before empty (size > MAX comes before size === 0)
		it('should report size error for oversized files even with valid type', () => {
			const file = createMockFile('big.png', 20 * 1024 * 1024, 'image/png');
			const result = validateImageFile(file);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('too large');
		});
	});
});
