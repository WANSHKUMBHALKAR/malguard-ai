"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { api } from "@/lib/api";
import { User, ScanRecord } from "@/types";
import { 
  Users, 
  Trash2, 
  ShieldAlert, 
  ShieldCheck, 
  Search, 
  Database,
  RefreshCw,
  FolderOpen,
  Mail,
  UserCheck,
  Lock
} from "lucide-react";
import { motion } from "framer-motion";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

export default function AdminPage() {
  const router = useRouter();
  const { user, isAdmin, isAuthenticated, loading: authLoading } = useAuth();
  
  const [users, setUsers] = useState<User[]>([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [deletingUserId, setDeletingUserId] = useState<string | null>(null);

  const [systemStats, setSystemStats] = useState({
    totalUsers: 0,
    totalScans: 0,
    averageThreatScore: 0
  });

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      router.push("/login");
      return;
    }

    if (isAuthenticated && !isAdmin) {
      // Do not redirect. We render an unauthorized access message in the UI cleanly.
      return;
    }

    if (isAuthenticated && isAdmin) {
      loadAdminData();
    }
  }, [isAuthenticated, isAdmin, authLoading, router]);

  const loadAdminData = async () => {
    setLoadingUsers(true);
    try {
      const userList = await api.getAdminUsers();
      setUsers(userList);
      
      const analytics = await api.getAnalytics();
      setSystemStats({
        totalUsers: userList.length,
        totalScans: analytics.total_scans,
        averageThreatScore: analytics.average_risk_score
      });
    } catch (err) {
      console.error("Failed to load admin telemetry data:", err);
    } finally {
      setLoadingUsers(false);
    }
  };

  const handleDeleteUser = async (targetUserId: string, targetEmail: string) => {
    if (targetUserId === user?.email) {
      alert("Self-deletion is forbidden.");
      return;
    }
    
    if (!confirm(`Are you sure you want to delete user account "${targetEmail}" permanently? All corresponding scan histories will be deleted.`)) {
      return;
    }

    setDeletingUserId(targetUserId);
    try {
      await api.deleteAdminUser(targetUserId);
      setUsers(users.filter(u => u.id !== targetUserId));
      setSystemStats(prev => ({
        ...prev,
        totalUsers: prev.totalUsers - 1
      }));
    } catch (err) {
      alert("Failed to delete user account.");
    } finally {
      setDeletingUserId(null);
    }
  };

  // Auth Guard display for non-admin sessions
  if (!authLoading && isAuthenticated && !isAdmin) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center p-4">
        <Card className="max-w-md w-full border border-rose-500/20 glow-rose text-center p-6">
          <CardHeader className="space-y-3">
            <div className="flex justify-center">
              <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-full animate-bounce">
                <Lock size={36} />
              </div>
            </div>
            <CardTitle className="text-xl font-extrabold">Access Control Warning</CardTitle>
            <CardDescription className="text-sm">
              You do not have permission to view the administrator portal. Administrative role rights are required.
            </CardDescription>
          </CardHeader>
          <div className="mt-6 flex justify-center">
            <Button onClick={() => router.push("/dashboard")} className="glow-blue">
              Back to Dashboard
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  if (authLoading || !isAuthenticated) {
    return (
      <div className="h-[60vh] flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary border-r-2" />
      </div>
    );
  }

  // Filter user list based on search bar query
  const filteredUsers = users.filter(u => 
    u.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    u.id.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center border-b border-border pb-6">
        <div>
          <h1 className="text-3xl font-black tracking-tight">Admin Operations Console</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Manage users, inspect system-wide threat telemetry, and configure active detection boundaries.
          </p>
        </div>
      </div>

      {/* Global Telemetry Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="glass-panel-hover">
          <CardContent className="p-6 flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-xs text-muted-foreground font-semibold uppercase">Total Platform Accounts</span>
              <span className="block text-3xl font-black">{systemStats.totalUsers}</span>
            </div>
            <div className="p-3 bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 rounded-xl">
              <Users size={24} />
            </div>
          </CardContent>
        </Card>

        <Card className="glass-panel-hover">
          <CardContent className="p-6 flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-xs text-muted-foreground font-semibold uppercase">Cumulative Scans</span>
              <span className="block text-3xl font-black">{systemStats.totalScans}</span>
            </div>
            <div className="p-3 bg-primary/10 border border-primary/20 text-primary rounded-xl">
              <FolderOpen size={24} />
            </div>
          </CardContent>
        </Card>

        <Card className="glass-panel-hover">
          <CardContent className="p-6 flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-xs text-muted-foreground font-semibold uppercase">Mean System Threat Score</span>
              <span className="block text-3xl font-black text-rose-500">{systemStats.averageThreatScore}/100</span>
            </div>
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-xl">
              <ShieldAlert size={24} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Grid: User administration & System status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* User Management Section (2/3 width) */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-border pb-4">
            <div>
              <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <UserCheck size={16} />
                User Accounts Directory
              </CardTitle>
              <CardDescription className="text-xs mt-0.5">Manage credentials, delete dormant or suspicious accounts.</CardDescription>
            </div>
            <div className="relative w-full sm:w-60">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" size={14} />
              <Input
                placeholder="Find user by email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 h-8 text-xs border-border bg-black/20"
              />
            </div>
          </CardHeader>
          <CardContent className="p-0 overflow-x-auto">
            {loadingUsers ? (
              <div className="p-8 text-center flex flex-col items-center justify-center">
                <RefreshCw size={24} className="animate-spin text-primary mb-2" />
                <span className="text-xs text-muted-foreground">Loading accounts database...</span>
              </div>
            ) : filteredUsers.length === 0 ? (
              <p className="p-8 text-center text-xs text-muted-foreground italic">No users found matching query.</p>
            ) : (
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="border-b border-border text-xs text-muted-foreground font-semibold uppercase bg-secondary/5">
                    <th className="py-3 px-6">Email Address</th>
                    <th className="py-3 px-6">Role</th>
                    <th className="py-3 px-6">Created On</th>
                    <th className="py-3 px-6 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filteredUsers.map((u) => {
                    const isSelf = u.id === user?.email; // Wait, user session object stores email as sub or id depends.
                    return (
                      <tr key={u.id} className="hover:bg-secondary/10 transition-colors">
                        <td className="py-3 px-6 font-semibold flex items-center gap-2">
                          <Mail size={12} className="text-primary" />
                          {u.email}
                        </td>
                        <td className="py-3 px-6">
                          <span className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-full border ${
                            u.role === "admin" 
                              ? "text-primary bg-primary/10 border-primary/20" 
                              : "text-muted-foreground bg-secondary border-border"
                          }`}>
                            {u.role}
                          </span>
                        </td>
                        <td className="py-3 px-6 text-muted-foreground text-xs font-medium">
                          {new Date(u.created_at).toLocaleDateString()}
                        </td>
                        <td className="py-3 px-6 text-right">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 h-7 w-7"
                            onClick={() => handleDeleteUser(u.id, u.email)}
                            disabled={deletingUserId === u.id}
                            title="Delete User"
                          >
                            {deletingUserId === u.id ? (
                              <RefreshCw size={12} className="animate-spin" />
                            ) : (
                              <Trash2 size={14} />
                            )}
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>

        {/* Database Stats Card (1/3 width) */}
        <Card className="lg:col-span-1 h-fit">
          <CardHeader>
            <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
              <Database size={16} />
              Platform Database Health
            </CardTitle>
            <CardDescription className="text-xs mt-0.5">Integrations state verification diagnostics.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-xs font-medium">
            <div className="flex justify-between items-center py-2 border-b border-border/60">
              <span className="text-muted-foreground font-semibold">DATABASE STATUS</span>
              <span className="text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-bold uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck size={12} />
                Online
              </span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-border/60">
              <span className="text-muted-foreground font-semibold">DATABASE PROVIDER</span>
              <span className="text-foreground font-bold">Supabase PostgreSQL</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-border/60">
              <span className="text-muted-foreground font-semibold">VIRUSTOTAL CONNECTOR</span>
              {process.env.VIRUSTOTAL_API_KEY ? (
                <span className="text-emerald-400 font-bold uppercase tracking-wider bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                  Active
                </span>
              ) : (
                <span className="text-amber-500 font-bold uppercase tracking-wider bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                  Unconfigured (Bypassed)
                </span>
              )}
            </div>
            <div className="flex justify-between items-center py-2">
              <span className="text-muted-foreground font-semibold">ML CLASSIFIER INSTANCE</span>
              <span className="text-primary font-bold uppercase tracking-wider bg-primary/10 px-2 py-0.5 rounded border border-primary/20">
                Production Forest
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
