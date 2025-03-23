import { LoginCredentials, RegisterCredentials } from "@shared/schema";

/**
 * Get the stored authentication token
 */
export function getToken(): string | null {
  return localStorage.getItem('token');
}

/**
 * Store the authentication token
 */
export function setToken(token: string): void {
  localStorage.setItem('token', token);
}

/**
 * Remove the authentication token
 */
export function removeToken(): void {
  localStorage.removeItem('token');
}

/**
 * Check if the user is authenticated by verifying token existence
 */
export function isAuthenticated(): boolean {
  return !!getToken();
}

/**
 * Set headers with authorization token
 */
export function getAuthHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

/**
 * Parse and decode JWT to get user information
 * Note: This is a client-side only JWT parsing, not verification
 */
export function parseJWT(token: string): any {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => `%${`00${c.charCodeAt(0).toString(16)}`.slice(-2)}`)
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('Error parsing JWT:', error);
    return null;
  }
}
