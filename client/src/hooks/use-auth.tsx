import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { apiRequest, queryClient } from '@/lib/queryClient';
import { LoginCredentials, RegisterCredentials } from '@shared/schema';

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: any;
  token: string | null;
  login: (credentials: LoginCredentials) => Promise<any>;
  register: (credentials: RegisterCredentials) => Promise<any>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(!!token);

  // User data query
  const { data: user, isLoading, refetch } = useQuery({
    queryKey: ['/api/user'],
    enabled: !!token,
  });

  // Login mutation
  const loginMutation = useMutation({
    mutationFn: async (credentials: LoginCredentials) => {
      const response = await apiRequest('POST', '/api/auth/login', credentials);
      return await response.json();
    },
    onSuccess: (data) => {
      setToken(data.token);
      localStorage.setItem('token', data.token);
      setIsAuthenticated(true);
      refetch();
    },
  });

  // Register mutation
  const registerMutation = useMutation({
    mutationFn: async (credentials: RegisterCredentials) => {
      const response = await apiRequest('POST', '/api/auth/register', credentials);
      return await response.json();
    },
    onSuccess: (data) => {
      setToken(data.token);
      localStorage.setItem('token', data.token);
      setIsAuthenticated(true);
      refetch();
    }
  });

  // Set authorization header for all requests
  useEffect(() => {
    const originalFetch = window.fetch;
    window.fetch = async (input, init) => {
      const adjustedInit = init || {};
      if (token && !adjustedInit.headers?.hasOwnProperty('Authorization')) {
        adjustedInit.headers = {
          ...adjustedInit.headers,
          'Authorization': `Bearer ${token}`
        };
      }
      return originalFetch(input, adjustedInit);
    };

    return () => {
      window.fetch = originalFetch;
    };
  }, [token]);

  // Check authentication status on mount
  useEffect(() => {
    if (token && !user && !isLoading) {
      refetch();
    }
  }, [token, user, isLoading, refetch]);

  // Logout function
  const logout = () => {
    setToken(null);
    setIsAuthenticated(false);
    localStorage.removeItem('token');
    queryClient.clear();
  };

  // Login function
  const login = async (credentials: LoginCredentials) => {
    return loginMutation.mutateAsync(credentials);
  };

  // Register function
  const register = async (credentials: RegisterCredentials) => {
    return registerMutation.mutateAsync(credentials);
  };

  const contextValue = {
    isAuthenticated,
    isLoading: isLoading && !!token,
    user,
    token,
    login,
    register,
    logout
  };

  if (isLoading && !!token) {
    return <div className="flex h-screen items-center justify-center">Loading...</div>;
  }

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}