import { describe, it, expect, vi } from 'vitest';
import { getHelpfulErrorMessage, extractErrorMessage } from './errorMessages.js';

describe('getHelpfulErrorMessage', () => {
	describe('specific status codes', () => {
		it('should return message for 400 Bad Request', () => {
			const msg = getHelpfulErrorMessage(400);
			expect(msg).toContain('Bad request');
			expect(msg).toContain('Invalid input');
		});

		it('should return message for 401 Unauthorized', () => {
			const msg = getHelpfulErrorMessage(401, 'uploading photos');
			expect(msg).toContain('Authentication required');
			expect(msg).toContain('log in');
			expect(msg).toContain('uploading photos');
		});

		it('should return message for 403 Forbidden', () => {
			const msg = getHelpfulErrorMessage(403, 'delete this artwork');
			expect(msg).toContain('Access denied');
			expect(msg).toContain('permission');
			expect(msg).toContain('delete this artwork');
		});

		it('should return message for 404 Not Found', () => {
			const msg = getHelpfulErrorMessage(404);
			expect(msg).toContain("doesn't exist");
		});

		it('should return message for 409 Conflict', () => {
			const msg = getHelpfulErrorMessage(409);
			expect(msg).toContain('Conflict');
			expect(msg).toContain('duplicates');
		});

		it('should return message for 413 Payload Too Large', () => {
			const msg = getHelpfulErrorMessage(413);
			expect(msg).toContain('File too large');
			expect(msg).toContain('size limit');
		});

		it('should return message for 415 Unsupported Media Type', () => {
			const msg = getHelpfulErrorMessage(415);
			expect(msg).toContain('Unsupported file type');
			expect(msg).toContain('JPEG');
			expect(msg).toContain('PNG');
		});

		it('should return message for 422 Unprocessable Entity', () => {
			const msg = getHelpfulErrorMessage(422);
			expect(msg).toContain('Validation error');
			expect(msg).toContain('invalid');
		});

		it('should return message for 429 Too Many Requests', () => {
			const msg = getHelpfulErrorMessage(429);
			expect(msg).toContain('Rate limit');
			expect(msg).toContain('Too many requests');
		});

		it('should return message for 500 Internal Server Error', () => {
			const msg = getHelpfulErrorMessage(500);
			expect(msg).toContain('Server error');
			expect(msg).toContain('try again');
		});

		it('should return message for 502 Bad Gateway', () => {
			const msg = getHelpfulErrorMessage(502);
			expect(msg).toContain('Bad gateway');
			expect(msg).toContain('temporarily unavailable');
		});

		it('should return message for 503 Service Unavailable', () => {
			const msg = getHelpfulErrorMessage(503);
			expect(msg).toContain('Service unavailable');
			expect(msg).toContain('maintenance');
		});

		it('should return message for 504 Gateway Timeout', () => {
			const msg = getHelpfulErrorMessage(504);
			expect(msg).toContain('Gateway timeout');
			expect(msg).toContain('took too long');
		});
	});

	describe('Retry-After header', () => {
		it('should include retry time when Retry-After header present', () => {
			const mockResponse = {
				headers: {
					get: vi.fn().mockReturnValue('30')
				}
			};
			const msg = getHelpfulErrorMessage(429, 'performing this action', mockResponse);
			expect(msg).toContain('30 seconds');
		});

		it('should work without Retry-After header', () => {
			const mockResponse = {
				headers: {
					get: vi.fn().mockReturnValue(null)
				}
			};
			const msg = getHelpfulErrorMessage(429, 'performing this action', mockResponse);
			expect(msg).toContain('Rate limit');
			expect(msg).not.toContain('seconds');
		});
	});

	describe('custom context', () => {
		it('should use default context when not provided', () => {
			const msg = getHelpfulErrorMessage(401);
			expect(msg).toContain('performing this action');
		});

		it('should use custom context when provided', () => {
			const msg = getHelpfulErrorMessage(401, 'viewing private gallery');
			expect(msg).toContain('viewing private gallery');
		});
	});

	describe('unknown status codes', () => {
		it('should handle unknown 4xx errors', () => {
			const msg = getHelpfulErrorMessage(418, 'brewing coffee');
			expect(msg).toContain('Request error');
			expect(msg).toContain('HTTP 418');
			expect(msg).toContain('brewing coffee');
		});

		it('should handle unknown 5xx errors', () => {
			const msg = getHelpfulErrorMessage(599);
			expect(msg).toContain('Server error');
			expect(msg).toContain('HTTP 599');
		});

		it('should handle non-error status codes gracefully', () => {
			const msg = getHelpfulErrorMessage(200);
			expect(msg).toContain('Unexpected error');
		});

		it('should handle status code 0 (network error)', () => {
			const msg = getHelpfulErrorMessage(0);
			expect(msg).toContain('Unexpected error');
		});
	});
});

describe('extractErrorMessage', () => {
	// Helper to create mock Response objects
	const createMockResponse = (status, body, contentType = 'application/json') => ({
		status,
		headers: {
			get: vi.fn().mockImplementation((header) => {
				if (header.toLowerCase() === 'content-type') return contentType;
				if (header.toLowerCase() === 'retry-after') return null;
				return null;
			})
		},
		json: vi.fn().mockResolvedValue(body),
		text: vi.fn().mockResolvedValue(JSON.stringify(body))
	});

	describe('JSON responses', () => {
		it('should extract error from JSON response with error field', async () => {
			const response = createMockResponse(400, { error: 'Email already exists' });
			const msg = await extractErrorMessage(response, 'registering');
			expect(msg).toContain('Email already exists');
		});

		it('should extract error from JSON response with message field', async () => {
			const response = createMockResponse(400, { message: 'Invalid input format' });
			const msg = await extractErrorMessage(response, 'submitting form');
			expect(msg).toContain('Invalid input format');
		});

		it('should fall back to helpful message if no error in JSON', async () => {
			const response = createMockResponse(500, { success: false });
			const msg = await extractErrorMessage(response, 'saving data');
			expect(msg).toContain('Server error');
		});
	});

	describe('non-JSON responses', () => {
		it('should handle HTML error pages', async () => {
			const response = createMockResponse(500, null, 'text/html');
			response.json = vi.fn().mockRejectedValue(new Error('Not JSON'));
			const msg = await extractErrorMessage(response, 'loading page');
			expect(msg).toContain('Server error');
		});

		it('should handle plain text responses', async () => {
			const response = createMockResponse(404, null, 'text/plain');
			response.json = vi.fn().mockRejectedValue(new Error('Not JSON'));
			const msg = await extractErrorMessage(response, 'finding resource');
			expect(msg).toContain("doesn't exist");
		});
	});

	describe('edge cases', () => {
		it('should handle response with empty body', async () => {
			const response = createMockResponse(401, {});
			const msg = await extractErrorMessage(response, 'accessing account');
			expect(msg).toContain('Authentication required');
		});

		it('should handle JSON parse errors gracefully', async () => {
			const response = createMockResponse(400, null, 'application/json');
			response.json = vi.fn().mockRejectedValue(new SyntaxError('Unexpected token'));
			const msg = await extractErrorMessage(response, 'parsing data');
			expect(msg).toContain('Bad request');
		});

		it('should use default context when not provided', async () => {
			const response = createMockResponse(403, { error: 'Forbidden' });
			const msg = await extractErrorMessage(response);
			expect(msg).toContain('complete this action');
		});
	});

	describe('combined messages', () => {
		it('should combine server error with helpful suggestion', async () => {
			const response = createMockResponse(401, { error: 'Session expired' });
			const msg = await extractErrorMessage(response, 'editing profile');
			expect(msg).toContain('Session expired');
			expect(msg).toContain('log in');
		});
	});
});
