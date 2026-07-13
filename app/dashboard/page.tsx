"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { api } from "@/lib/api";
import { AnalyticsSummary } from "@/types";
import { 
  ShieldAlert, 
  Activity, 
  BarChart4, 
  FileCheck, 
  AlertTriangle,
  FolderOpen,
  PieChart as PieIcon,
  HelpCircle,
  Database
} from "lucide-react";
import { motion } from "framer-motion";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

// Recharts components
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
  Legend
} from "recharts";

const COLORS = [
  "#38bdf8", // Benign (Clean) - Sky
  "#ef4444", // Trojan - Red
  "#f97316", // Worm - Orange
  "#f59e0b", // Spyware - Amber
  "#ec4899", // Ransomware - Pink
  "#a855f7", // Adware - Purple
  "#6366f1", // Backdoor - Indigo
  "#14b8a6", // Downloader - Teal
  "#22c55e", // Cryptominer - Green
  "#e11d48"  // Botnet - Rose
];

export default function DashboardPage() {
  const router = useRouter();
  const { isAuthenticated, loading: authLoading } = useAuth();
  
  const [data, setData] = useState<AnalyticsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [dbError, setDbError] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (mounted && !authLoading && !isAuthenticated) {
      router.push("/login");
      return;
    }

    if (mounted && isAuthenticated) {
      fetchAnalytics();
    }
  }, [isAuthenticated, authLoading, router, mounted]);

  const fetchAnalytics = async () => {
    setLoading(true);
    setDbError(false);
    try {
      const summary = await api.getAnalytics();
      setData(summary);
    } catch (err: any) {
      if (err.message && err.message.includes("database connection is unconfigured")) {
        setDbError(true);
      }
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (authLoading || !isAuthenticated || !mounted) {
    return (
      <div className="h-[60vh] flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary border-r-2" />
      </div>
    );
  }

  // Render Database Setup Error Modal if credentials are missing
  if (dbError) {
    return (
      <div className="min-h-[70vh] flex items-center justify-center p-4">
        <Card className="max-w-xl w-full border border-rose-500/20 glow-rose p-6">
          <CardHeader className="text-center space-y-3">
            <div className="flex justify-center">
              <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-full animate-bounce">
                <Database size={36} />
              </div>
            </div>
            <CardTitle className="text-xl font-extrabold text-foreground">Database Setup Required</CardTitle>
            <CardDescription className="text-sm">
              MalGuard AI relies on a Supabase PostgreSQL database to log reports and manage authentication. 
              The connection is currently unconfigured.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-sm text-muted-foreground bg-black/30 p-4 rounded-lg border border-border">
            <h4 className="font-bold text-foreground mb-1 text-xs uppercase tracking-wider">How to resolve:</h4>
            <ol className="list-decimal pl-4 space-y-2 text-xs">
              <li>Create a free PostgreSQL project on <a href="https://supabase.com" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">supabase.com</a>.</li>
              <li>Execute the SQL initialization queries provided in the <code className="bg-secondary px-1 py-0.5 rounded font-mono text-primary">README.md</code>.</li>
              <li>Copy <code className="bg-secondary px-1 py-0.5 rounded font-mono">.env.example</code> to <code className="bg-secondary px-1 py-0.5 rounded font-mono">.env</code> in your project root.</li>
              <li>Insert your project credentials for <code className="bg-secondary px-1 py-0.5 rounded font-mono">NEXT_PUBLIC_SUPABASE_URL</code> and <code className="bg-secondary px-1 py-0.5 rounded font-mono">NEXT_PUBLIC_SUPABASE_ANON_KEY</code>.</li>
              <li>Restart the development server.</li>
            </ol>
          </CardContent>
          <div className="mt-6 flex justify-center">
            <Button onClick={fetchAnalytics} className="glow-blue">
              Retry Connection
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  // Helper data processing
  const totalScans = data?.total_scans || 0;
  const avgRisk = data?.average_risk_score || 0;
  const maliciousCount = data ? Object.entries(data.malware_family_distribution)
    .filter(([name]) => name !== "Benign")
    .reduce((sum, [_, count]) => sum + count, 0) : 0;
  const benignCount = data?.malware_family_distribution["Benign"] || 0;

  // Prepare Family distribution pie chart data
  const pieData = data ? Object.entries(data.malware_family_distribution).map(([name, value]) => ({
    name,
    value
  })) : [];

  // Prepare Threat Level distribution bar data
  const barData = data ? Object.entries(data.threat_level_distribution).map(([name, value]) => ({
    name,
    value
  })) : [];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
  };

  const cardVariants = {
    hidden: { y: 15, opacity: 0 },
    visible: { y: 0, opacity: 1 }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner Dashboard header */}
      <div className="flex justify-between items-center border-b border-border pb-6">
        <div>
          <h1 className="text-3xl font-black tracking-tight">Security Analytics Dashboard</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Real-time telemetry and machine learning detection telemetry.
          </p>
        </div>
        <Button onClick={() => router.push("/scan")} className="glow-blue">
          Scan New Binary
        </Button>
      </div>

      {loading ? (
        // Skeleton loader grid
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {[...Array(4)].map((_, i) => (
            <Card key={i} className="shimmer h-28" />
          ))}
          <Card className="shimmer h-[350px] md:col-span-2" />
          <Card className="shimmer h-[350px] md:col-span-2" />
        </div>
      ) : (
        <motion.div 
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="space-y-6"
        >
          {/* Stats Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <motion.div variants={cardVariants}>
              <Card className="glass-panel-hover">
                <CardContent className="p-6 flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="text-xs text-muted-foreground font-semibold uppercase">Total Scans</span>
                    <span className="block text-3xl font-black">{totalScans}</span>
                  </div>
                  <div className="p-3 bg-primary/10 border border-primary/20 text-primary rounded-xl">
                    <FolderOpen size={24} />
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={cardVariants}>
              <Card className="glass-panel-hover">
                <CardContent className="p-6 flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="text-xs text-muted-foreground font-semibold uppercase">Average Risk</span>
                    <span className="block text-3xl font-black">{avgRisk}/100</span>
                  </div>
                  <div className={`p-3 rounded-xl border ${
                    avgRisk > 60 ? "bg-rose-500/10 border-rose-500/20 text-rose-500" :
                    avgRisk > 30 ? "bg-amber-500/10 border-amber-500/20 text-amber-500" :
                    "bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
                  }`}>
                    <Activity size={24} />
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={cardVariants}>
              <Card className="glass-panel-hover">
                <CardContent className="p-6 flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="text-xs text-muted-foreground font-semibold uppercase">Malicious Files</span>
                    <span className="block text-3xl font-black text-rose-500">{maliciousCount}</span>
                  </div>
                  <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-xl">
                    <ShieldAlert size={24} />
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={cardVariants}>
              <Card className="glass-panel-hover">
                <CardContent className="p-6 flex items-center justify-between">
                  <div className="space-y-1">
                    <span className="text-xs text-muted-foreground font-semibold uppercase">Clean Files</span>
                    <span className="block text-3xl font-black text-emerald-400">{benignCount}</span>
                  </div>
                  <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl">
                    <FileCheck size={24} />
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Timeline Area Chart */}
          <motion.div variants={cardVariants}>
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
                  <BarChart4 size={16} />
                  Threat Detection Timeline
                </CardTitle>
                <CardDescription>Metrics indicating scan volume and threat findings over the last 14 active days.</CardDescription>
              </CardHeader>
              <CardContent className="h-[280px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={data?.timeline} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <defs>
                      <linearGradient id="scansGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#0284c7" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#0284c7" stopOpacity={0}/>
                      </linearGradient>
                      <linearGradient id="malGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="date" stroke="#475569" fontSize={10} tickLine={false} />
                    <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                    <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b", color: "#f8fafc" }} />
                    <Legend wrapperStyle={{ fontSize: "11px", paddingTop: "10px" }} />
                    <Area type="monotone" name="Total Scans" dataKey="scans" stroke="#0284c7" fillOpacity={1} fill="url(#scansGrad)" strokeWidth={2} />
                    <Area type="monotone" name="Malicious Blocked" dataKey="malicious" stroke="#ef4444" fillOpacity={1} fill="url(#malGrad)" strokeWidth={2} />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </motion.div>

          {/* Bottom Grid: Family Pie Chart & Threat Level Bar Chart */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <motion.div variants={cardVariants}>
              <Card className="h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
                    <PieIcon size={16} />
                    Malware Family Distribution
                  </CardTitle>
                  <CardDescription>Visual breakdown of classified binary families from repository scans.</CardDescription>
                </CardHeader>
                <CardContent className="h-[280px] flex items-center justify-center">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }} />
                      <Legend 
                        layout="vertical"
                        align="right"
                        verticalAlign="middle"
                        iconType="circle"
                        wrapperStyle={{ fontSize: "11px", paddingLeft: "10px" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </motion.div>

            <motion.div variants={cardVariants}>
              <Card className="h-full">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
                    <AlertTriangle size={16} />
                    Threat Severity Distribution
                  </CardTitle>
                  <CardDescription>Telemetry displaying threat counts organized by severity scores.</CardDescription>
                </CardHeader>
                <CardContent className="h-[280px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={barData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                      <XAxis dataKey="name" stroke="#475569" fontSize={10} tickLine={false} />
                      <YAxis stroke="#475569" fontSize={10} tickLine={false} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }} />
                      <Bar dataKey="value" name="Threat Count" radius={[4, 4, 0, 0]}>
                        {barData.map((entry, index) => {
                          let barColor = "#38bdf8"; // Clean
                          if (entry.name === "Critical") barColor = "#ef4444";
                          else if (entry.name === "High") barColor = "#f97316";
                          else if (entry.name === "Medium") barColor = "#f59e0b";
                          else if (entry.name === "Low") barColor = "#84cc16";
                          return <Cell key={`cell-${index}`} fill={barColor} />;
                        })}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </motion.div>
      )}
    </div>
  );
}
