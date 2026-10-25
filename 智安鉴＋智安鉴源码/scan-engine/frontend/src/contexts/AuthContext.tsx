import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

export interface User {
  id: string;
  username: string;
  email: string;
  role: 'user' | 'admin';
  is_active: boolean;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
}

export interface AuthToken {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
}

interface AuthContextType {
  user: User | null;
  token: AuthToken | null;
  loading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, email: string, password: string, password_confirm: string) => Promise<void>;
  logout: () => void;
  updateProfile: (email?: string, username?: string, password?: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const STORAGE_KEY_TOKEN = 'auth_token';
const STORAGE_KEY_USER = 'auth_user';
const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<AuthToken | null>(null);
  const [loading, setLoading] = useState(true);

  // 初始化：从 localStorage 恢复 token 和 user
  useEffect(() => {
    console.log('[AuthProvider] Initializing auth state from localStorage');
    const storedToken = localStorage.getItem(STORAGE_KEY_TOKEN);
    const storedUser = localStorage.getItem(STORAGE_KEY_USER);

    console.log('[AuthProvider] Found stored data:', {
      hasToken: !!storedToken,
      hasUser: !!storedUser
    });

    if (storedToken && storedUser) {
      try {
        const parsedToken = JSON.parse(storedToken);
        const parsedUser = JSON.parse(storedUser);
        setToken(parsedToken);
        setUser(parsedUser);
        console.log('[AuthProvider] Restored auth state:', {
          userId: parsedUser.id,
          username: parsedUser.username
        });
      } catch (error) {
        console.error('[AuthProvider] Failed to restore auth state:', error);
        localStorage.removeItem(STORAGE_KEY_TOKEN);
        localStorage.removeItem(STORAGE_KEY_USER);
      }
    }

    console.log('[AuthProvider] Setting loading to false');
    setLoading(false);
  }, []);

  const login = async (username: string, password: string) => {
    try {
      console.log('[Auth] Logging in user:', username);
      console.log('[Auth] API_BASE:', API_BASE);
      
      const controller = new AbortController();
      // 增加到30秒超时以适应首次启动时数据库初始化的延迟
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.json();
        console.error('[Auth] Login failed:', error);
        throw new Error(error.detail || '登录失败');
      }

      const data = await response.json();
      console.log('[Auth] Login successful');
      
      setUser(data.user);
      setToken(data.token);

      localStorage.setItem(STORAGE_KEY_TOKEN, JSON.stringify(data.token));
      localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(data.user));
    } catch (error) {
      console.error('[Auth] Login error:', error);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('登录请求超时，请确保后端服务已启动');
      }
      throw error;
    }
  };

  const register = async (
    username: string,
    email: string,
    password: string,
    password_confirm: string
  ) => {
    try {
      console.log('[Auth] Registering user:', username);
      
      const controller = new AbortController();
      // 30秒超时
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, password_confirm }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.json();
        console.error('[Auth] Register failed:', error);
        throw new Error(error.detail || '注册失败');
      }

      const data = await response.json();
      console.log('[Auth] Register successful');
      
      setUser(data.user);
      setToken(data.token);

      localStorage.setItem(STORAGE_KEY_TOKEN, JSON.stringify(data.token));
      localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(data.user));
    } catch (error) {
      console.error('[Auth] Register error:', error);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('注册请求超时，请确保后端服务已启动');
      }
      throw error;
    }
  };

  const logout = () => {
    console.log('[Auth] Logging out');
    setUser(null);
    setToken(null);
    localStorage.removeItem(STORAGE_KEY_TOKEN);
    localStorage.removeItem(STORAGE_KEY_USER);
  };

  const updateProfile = async (email?: string, username?: string, password?: string) => {
    if (!token) throw new Error('未认证');

    try {
      console.log('[Auth] Updating profile');
      
      const controller = new AbortController();
      // 30秒超时
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const response = await fetch(`${API_BASE}/auth/profile`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token.access_token}`,
        },
        body: JSON.stringify({ email, username, password }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const error = await response.json();
        console.error('[Auth] Update failed:', error);
        throw new Error(error.detail || '更新失败');
      }

      const updatedUser = await response.json();
      console.log('[Auth] Profile updated');
      
      setUser(updatedUser);
      localStorage.setItem(STORAGE_KEY_USER, JSON.stringify(updatedUser));
    } catch (error) {
      console.error('[Auth] Update error:', error);
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('更新请求超时，请确保后端服务已启动');
      }
      throw error;
    }
  };

  const value: AuthContextType = {
    user,
    token,
    loading,
    isAuthenticated: !!token && !!user,
    isAdmin: user?.role === 'admin',
    login,
    register,
    logout,
    updateProfile,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
