const BASE_URL = ""; // Relative URL maps to Vercel rewrite or Next.js proxy

function getHeaders(isMultipart = false): HeadersInit {
  const headers: Record<string, string> = {};
  
  if (!isMultipart) {
    headers["Content-Type"] = "application/json";
  }
  
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("malguard_token");
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
  }
  
  return headers;
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let errorMessage = "An error occurred during the request.";
    try {
      const errorData = await response.json();
      errorMessage = errorData.detail || errorMessage;
    } catch {
      // Keep default error
    }
    
    if (response.status === 401 && typeof window !== "undefined") {
      localStorage.removeItem("malguard_token");
      localStorage.removeItem("malguard_user");
      window.dispatchEvent(new Event("auth-changed"));
    }
    
    throw new Error(errorMessage);
  }
  
  return response.json() as Promise<T>;
}

export const api = {
  // Authentication
  async register(email: string, password: string): Promise<{ message: string; role: string }> {
    const res = await fetch(`${BASE_URL}/api/auth/register`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ email, password }),
    });
    return handleResponse(res);
  },

  async login(email: string, password: string): Promise<{ access_token: string; email: string; role: string }> {
    const res = await fetch(`${BASE_URL}/api/auth/login`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify({ email, password }),
    });
    
    const data = await handleResponse<{ access_token: string; email: string; role: string }>(res);
    
    if (typeof window !== "undefined") {
      localStorage.setItem("malguard_token", data.access_token);
      localStorage.setItem("malguard_user", JSON.stringify({ email: data.email, role: data.role }));
      window.dispatchEvent(new Event("auth-changed"));
    }
    
    return data;
  },

  logout(): void {
    if (typeof window !== "undefined") {
      localStorage.removeItem("malguard_token");
      localStorage.removeItem("malguard_user");
      window.dispatchEvent(new Event("auth-changed"));
    }
  },

  getCurrentUser(): { email: string; role: string } | null {
    if (typeof window !== "undefined") {
      const userStr = localStorage.getItem("malguard_user");
      if (userStr) {
        try {
          return JSON.parse(userStr);
        } catch {
          return null;
        }
      }
    }
    return null;
  },

  // Scan Operations
  async scanFile(file: File): Promise<any> {
    const formData = new FormData();
    formData.append("file", file);
    
    const res = await fetch(`${BASE_URL}/api/scan`, {
      method: "POST",
      headers: getHeaders(true),
      body: formData,
    });
    return handleResponse(res);
  },

  async getScans(search?: string, classFilter?: string): Promise<any[]> {
    const params = new URLSearchParams();
    if (search) params.append("search", search);
    if (classFilter && classFilter !== "All") params.append("class_filter", classFilter);
    
    const res = await fetch(`${BASE_URL}/api/scans?${params.toString()}`, {
      method: "GET",
      headers: getHeaders(),
    });
    return handleResponse(res);
  },

  async getScanById(id: string): Promise<any> {
    const res = await fetch(`${BASE_URL}/api/scans/${id}`, {
      method: "GET",
      headers: getHeaders(),
    });
    return handleResponse(res);
  },

  async deleteScan(id: string): Promise<{ message: string }> {
    const res = await fetch(`${BASE_URL}/api/scans/${id}`, {
      method: "DELETE",
      headers: getHeaders(),
    });
    return handleResponse(res);
  },

  // Analytics
  async getAnalytics(): Promise<any> {
    const res = await fetch(`${BASE_URL}/api/analytics`, {
      method: "GET",
      headers: getHeaders(),
    });
    return handleResponse(res);
  },

  // Admin Operations
  async getAdminUsers(): Promise<any[]> {
    const res = await fetch(`${BASE_URL}/api/admin/users`, {
      method: "GET",
      headers: getHeaders(),
    });
    return handleResponse(res);
  },

  async deleteAdminUser(userId: string): Promise<{ message: string }> {
    const res = await fetch(`${BASE_URL}/api/admin/users/${userId}`, {
      method: "DELETE",
      headers: getHeaders(),
    });
    return handleResponse(res);
  },

  // Export Reports
  async downloadReport(scanId: string, format: "pdf" | "json" | "csv"): Promise<void> {
    const headers = getHeaders();
    const res = await fetch(`${BASE_URL}/api/scans/${scanId}/export?format=${format}`, {
      method: "GET",
      headers,
    });
    
    if (!res.ok) {
      throw new Error(`Failed to export report: ${res.statusText}`);
    }
    
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    
    const ext = format === "pdf" ? "pdf" : format === "json" ? "json" : "csv";
    a.download = `malguard_report_${scanId}.${ext}`;
    document.body.appendChild(a);
    a.click();
    
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }
};
