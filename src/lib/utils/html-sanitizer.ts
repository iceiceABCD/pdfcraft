/**
 * HTML Sanitization utilities
 * Prevents XSS attacks when rendering user-generated HTML content
 */

// Allowed HTML tags for safe rendering
const ALLOWED_TAGS = new Set([
  'p', 'br', 'b', 'i', 'u', 'strong', 'em', 'span', 'div',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'li',
  'a', 'img',
  'table', 'thead', 'tbody', 'tr', 'th', 'td',
  'blockquote', 'pre', 'code',
  'hr', 'sub', 'sup', 'mark',
]);

// Allowed attributes per tag
const ALLOWED_ATTRS: Record<string, Set<string>> = {
  '*': new Set(['class', 'id', 'style']),
  'a': new Set(['href', 'title', 'target', 'rel']),
  'img': new Set(['src', 'alt', 'width', 'height']),
  'td': new Set(['colspan', 'rowspan']),
  'th': new Set(['colspan', 'rowspan', 'scope']),
};

// Dangerous URL protocols
const DANGEROUS_PROTOCOLS = ['javascript:', 'data:', 'vbscript:'];

/**
 * Check if a URL is safe
 */
function isSafeUrl(url: string): boolean {
  const lowerUrl = url.toLowerCase().trim();
  return !DANGEROUS_PROTOCOLS.some(proto => lowerUrl.startsWith(proto));
}

/**
 * Sanitize HTML string to prevent XSS
 * Uses DOMParser for safe parsing
 */
export function sanitizeHtml(html: string): string {
  if (typeof window === 'undefined') {
    // Server-side: strip all HTML tags
    return html.replace(/<[^>]*>/g, '');
  }

  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  
  function sanitizeNode(node: Node): Node | null {
    if (node.nodeType === Node.TEXT_NODE) {
      return node.cloneNode(true);
    }
    
    if (node.nodeType !== Node.ELEMENT_NODE) {
      return null;
    }
    
    const element = node as Element;
    const tagName = element.tagName.toLowerCase();
    
    // Remove disallowed tags
    if (!ALLOWED_TAGS.has(tagName)) {
      const fragment = document.createDocumentFragment();
      element.childNodes.forEach(child => {
        const sanitized = sanitizeNode(child);
        if (sanitized) fragment.appendChild(sanitized);
      });
      return fragment;
    }
    
    // Create clean element
    const cleanElement = document.createElement(tagName);
    
    // Copy allowed attributes
    const globalAttrs = ALLOWED_ATTRS['*'];
    const tagAttrs = ALLOWED_ATTRS[tagName] || new Set();
    
    Array.from(element.attributes).forEach(attr => {
      const attrName = attr.name.toLowerCase();
      if (globalAttrs.has(attrName) || tagAttrs.has(attrName)) {
        // Validate URLs
        if ((attrName === 'href' || attrName === 'src') && !isSafeUrl(attr.value)) {
          return;
        }
        // Force safe link behavior
        if (attrName === 'href' && tagName === 'a') {
          cleanElement.setAttribute('rel', 'noopener noreferrer');
        }
        cleanElement.setAttribute(attrName, attr.value);
      }
    });
    
    // Recursively sanitize children
    element.childNodes.forEach(child => {
      const sanitized = sanitizeNode(child);
      if (sanitized) cleanElement.appendChild(sanitized);
    });
    
    return cleanElement;
  }
  
  const fragment = document.createDocumentFragment();
  doc.body.childNodes.forEach(child => {
    const sanitized = sanitizeNode(child);
    if (sanitized) fragment.appendChild(sanitized);
  });
  
  const container = document.createElement('div');
  container.appendChild(fragment);
  return container.innerHTML;
}

/**
 * Escape HTML entities for safe text display
 */
export function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, char => map[char]);
}
