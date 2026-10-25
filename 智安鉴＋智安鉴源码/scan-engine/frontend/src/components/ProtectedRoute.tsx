import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requireAdmin?: boolean;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ 
  children, 
  requireAdmin = false 
}) => {
  const { isAuthenticated, isAdmin, loading, user, token } = useAuth();

  console.log('[ProtectedRoute] State:', {
    loading,
    isAuthenticated,
    isAdmin,
    hasUser: !!user,
    hasToken: !!token,
    requireAdmin
  });

  if (loading) {
    console.log('[ProtectedRoute] Still loading, showing loading state');
    return <div className="loading">加载中...</div>;
  }

  if (!isAuthenticated) {
    console.log('[ProtectedRoute] Not authenticated, redirecting to /auth');
    return <Navigate to="/auth" replace />;
  }

  if (requireAdmin && !isAdmin) {
    console.log('[ProtectedRoute] Not admin but admin required, redirecting to /');
    return <Navigate to="/" replace />;
  }

  console.log('[ProtectedRoute] Access granted, rendering children');
  return <>{children}</>;
};
