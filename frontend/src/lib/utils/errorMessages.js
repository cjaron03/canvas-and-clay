/**
 * Generate helpful error messages with suggested fixes based on HTTP status codes
 * @param {number} status - HTTP status code
 * @param {string} context - Context of the error (e.g., "loading artworks", "uploading photo")
 * @param {Response} response - Optional response object to extract additional info
 * @returns {string} - Helpful error message with suggested fix
 */
export function getHelpfulErrorMessage(status, context = 'performing this action', response = null) {
  const retryAfter = response?.headers?.get('Retry-After');
  const retryMsg = retryAfter ? ` Please wait ${retryAfter} seconds before trying again.` : '';

  switch (status) {
    case 400:
      return `Bad request: Invalid input provided. Please check your data and try again.`;
    
    case 401:
      return `Authentication required: You need to log in to ${context}. Please log in and try again.`;
    
    case 403:
      return `Access denied: You don't have permission to ${context}. Contact an administrator if you believe this is an error.`;
    
    case 404:
      return `Huh, whatever you're looking for doesn't exist. Double check your URL or search for an item.`;
    
    case 409:
      return `Conflict: This action conflicts with existing data. Please check for duplicates or conflicting entries.`;
    
    case 413:
      return `File too large: The file you're trying to upload exceeds the size limit. Please use a smaller file.`;
    
    case 415:
      return `Unsupported file type: The file format is not supported. Please use a supported image format (JPEG, PNG, WebP, or AVIF).`;
    
    case 422:
      return `Validation error: The data you provided is invalid. Please check all fields and try again.`;
    
    case 429:
      return `Rate limit exceeded: Too many requests.${retryMsg} Suggestion: Wait a moment before refreshing or making more requests. If this persists, try again later.`;
    
    case 500:
      return `Server error: Something went wrong on our end. Please try again in a few moments. If the problem persists, contact support.`;
    
    case 502:
      return `Bad gateway: The server is temporarily unavailable. Please try again in a few moments.`;
    
    case 503:
      return `Service unavailable: The service is temporarily down for maintenance. Please try again later.`;
    
    case 504:
      return `Gateway timeout: The request took too long to process. Please try again.`;
    
    default:
      if (status >= 500) {
        return `Server error (HTTP ${status}): Something went wrong on our end. Please try again later. If the problem persists, contact support.`;
      } else if (status >= 400) {
        return `Request error (HTTP ${status}): ${context} failed. Please check your input and try again.`;
      } else {
        return `Unexpected error: Failed to ${context}. Please try again.`;
      }
  }
}

/**
 * Extract error message from response, with helpful suggestions
 * @param {Response} response - Fetch response object
 * @param {string} context - Context of the error
 * @returns {Promise<string>} - Error message with suggestions
 */
export async function extractErrorMessage(response, context = 'complete this action') {
  const status = response.status;
  
  // Try to get error message from response body
  let errorMessage = null;
  try {
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = await response.json();
      errorMessage = data.error || data.message;
    }
  } catch {
    // Ignore JSON parsing errors
  }
  
  // Use helpful error message with context
  const helpfulMessage = getHelpfulErrorMessage(status, context, response);
  
  // Combine with server-provided message if available
  if (errorMessage && errorMessage !== helpfulMessage) {
    return `${errorMessage}. ${helpfulMessage}`;
  }
  
  return helpfulMessage;
}

