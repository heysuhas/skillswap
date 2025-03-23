import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
 
/**
 * Combines class names with Tailwind merge support
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Format a date in a user-friendly way
 * @param date The date to format
 * @param includeTime Whether to include the time in the formatted string
 */
export function formatDate(date: Date | string, includeTime: boolean = false): string {
  const dateObj = date instanceof Date ? date : new Date(date);
  
  const options: Intl.DateTimeFormatOptions = {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  };
  
  if (includeTime) {
    options.hour = 'numeric';
    options.minute = '2-digit';
    options.hour12 = true;
  }
  
  return new Intl.DateTimeFormat('en-US', options).format(dateObj);
}

/**
 * Safely truncate a string to a specified length
 * @param str The string to truncate
 * @param length The maximum length of the string
 * @param ending The string to append to the end of the truncated string
 */
export function truncateString(str: string, length: number, ending: string = '...'): string {
  if (str.length > length) {
    return str.substring(0, length - ending.length) + ending;
  }
  return str;
}

/**
 * Get a user's initials from their name
 * @param name The user's name
 */
export function getInitials(name: string): string {
  if (!name) return '';
  
  const parts = name.split(' ');
  
  if (parts.length === 1) {
    return parts[0].charAt(0).toUpperCase();
  }
  
  return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
}

/**
 * Calculate time ago in a user-friendly format (e.g., "2 hours ago")
 * @param date The date to calculate from
 */
export function timeAgo(date: Date | string): string {
  const dateObj = date instanceof Date ? date : new Date(date);
  const now = new Date();
  
  const seconds = Math.floor((now.getTime() - dateObj.getTime()) / 1000);
  
  if (seconds < 60) return 'just now';
  
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;
  
  const weeks = Math.floor(days / 7);
  if (weeks < 4) return `${weeks} week${weeks > 1 ? 's' : ''} ago`;
  
  const months = Math.floor(days / 30);
  if (months < 12) return `${months} month${months > 1 ? 's' : ''} ago`;
  
  const years = Math.floor(days / 365);
  return `${years} year${years > 1 ? 's' : ''} ago`;
}
