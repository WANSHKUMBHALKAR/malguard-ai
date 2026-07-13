"use client";

import React, { createContext, useContext, useState, useEffect } from "react";
import { api } from "@/lib/api";

interface UserSession {
  email: string;
  role: string;
}

interface AuthContextType {
  user: UserSession | null;
  token: string | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<any>;
  register: (email: string, password: string) => Promise<any>;
  logout: () => void;
  isAuthenticated: boolean;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserSession | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const syncAuth = () => {
    if (typeof window !== "undefined") {
      const storedToken = localStorage.getItem("malguard_token");
      const storedUser = api.getCurrentUser();
      
      setToken(storedToken);
      setUser(storedUser);
      setLoading(false);
    }
  };

  useEffect(() => {
    syncAuth();
    
    // Listen for storage changes or custom auth events
    if (typeof window !== "undefined") {
      window.addEventListener("auth-changed", syncAuth);
      window.addEventListener("storage", syncAuth);
    }
    
    return () => {
      if (typeof window !== "undefined") {
        window.removeEventListener("auth-changed", syncAuth);
        window.removeEventListener("storage", syncAuth);
      }
    };
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    try {
      const data = await api.login(email, password);
      setToken(data.access_token);
      setUser({ email: data.email, role: data.role });
      return data;
    } catch (err) {
      setLoading(false);
      throw err;
    }
  };

  const register = async (email: string, password: string) => {
    return await api.register(email, password);
  };

  const logout = () => {
    api.logout();
    setToken(null);
    setUser(null);
  };

  const value = {
    user,
    token,
    loading,
    login,
    register,
    logout,
    isAuthenticated: !!token,
    isAdmin: user?.role === "admin",
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
