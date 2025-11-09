"""Security utilities for XSS protection and HTML sanitization.

This module provides defense-in-depth measures against XSS attacks.
Note: The frontend (Svelte) already safely escapes content, and Flask's
jsonify() escapes JSON special characters. These utilities provide additional
layers of protection.
"""
import html
import bleach


def escape_html(text):
    """Escape HTML special characters to prevent XSS attacks.
    
    This function escapes the following characters:
    - < becomes &lt;
    - > becomes &gt;
    - & becomes &amp;
    - " becomes &quot;
    - ' becomes &#x27;
    
    Note: This does NOT escape javascript: protocols in attributes.
    Protection relies on CSP headers and frontend safe rendering.
    
    Args:
        text: String to escape. If None, returns empty string.
        
    Returns:
        Escaped string safe for HTML rendering.
        
    Example:
        >>> escape_html("<script>alert('XSS')</script>")
        "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"
    """
    if text is None:
        return ''
    return html.escape(str(text), quote=True)


def sanitize_html(html_content, allowed_tags=None, allowed_attributes=None):
    """Sanitize HTML content by removing dangerous tags and attributes.
    
    By default, strips all HTML tags and returns plain text. This is the
    safest approach for user-generated content. If HTML content is needed
    in the future, allowed_tags and allowed_attributes can be configured.
    
    This function also removes javascript: protocols and data: URIs that
    could be used for XSS attacks.
    
    Args:
        html_content: HTML string to sanitize. If None, returns empty string.
        allowed_tags: List of allowed HTML tags (default: empty list - no HTML allowed).
        allowed_attributes: Dict mapping tags to allowed attributes (default: empty dict).
        
    Returns:
        Sanitized string with HTML tags removed (or allowed tags preserved if configured).
        
    Example:
        >>> sanitize_html("<script>alert('XSS')</script>Hello")
        "Hello"
        >>> sanitize_html("<p>Hello</p>", allowed_tags=['p'])
        "<p>Hello</p>"
    """
    if html_content is None:
        return ''
    
    # Default: strip all HTML (safest for user-generated content)
    if allowed_tags is None:
        allowed_tags = []
    if allowed_attributes is None:
        allowed_attributes = {}
    
    # Use bleach to sanitize HTML
    # If no allowed tags, this will strip all HTML and return plain text
    sanitized = bleach.clean(
        html_content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True,  # Remove tags that aren't in allowed_tags
        protocols=['http', 'https']  # Only allow http/https protocols, block javascript: and data:
    )
    
    # Additional cleanup: remove any remaining javascript: protocols
    # (bleach should handle this, but defense-in-depth)
    sanitized = sanitized.replace('javascript:', '')
    sanitized = sanitized.replace('JAVASCRIPT:', '')
    sanitized = sanitized.replace('JavaScript:', '')
    
    return sanitized

