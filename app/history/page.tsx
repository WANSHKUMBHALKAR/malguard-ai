"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { api } from "@/lib/api";
import { ScanRecord } from "@/types";
import { 
  Search, 
  Filter, 
  Trash2, 
  Eye, 
  Calendar, 
  FileCode, 
  ShieldCheck, 
  ShieldAlert, 
  X,
  RefreshCw,
  Clock,
  ArrowRight
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { RiskGauge } from "@/components/risk-gauge";
import { StaticReport } from "@/components/static-report";

const CLASSES = [
  "All", "Benign", "Trojan", "Worm", "Spyware", "Ransomware",
  "Adware", "Backdoor", "Downloader", "Cryptominer", "Botnet"
];

export default function HistoryPage() {
  const router = useRouter();
  const { isAuthenticated, loading: authLoading } = useAuth();
  
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedFilter, setSelectedFilter] = useState("All");
  
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      router.push("/login");
      return;
    }

    if (isAuthenticated) {
      fetchScans();
    }
  }, [isAuthenticated, authLoading, router, selectedFilter]);

  const fetchScans = async () => {
    setLoading(true);
    try {
      const records = await api.getScans(search, selectedFilter);
      setScans(records);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchScans();
  };

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation(); // Avoid triggering row selection
    if (!confirm("Are you sure you want to delete this scan record permanently?")) return;
    
    setDeletingId(id);
    try {
      await api.deleteScan(id);
      setScans(scans.filter(s => s.id !== id));
      if (selectedScan?.id === id) {
        setSelectedScan(null);
      }
    } catch (err) {
      alert("Failed to delete scan record.");
    } finally {
      setDeletingId(null);
    }
  };

  const getScoreColor = (score: number) => {
    if (score > 85) return "text-rose-500 bg-rose-500/10 border-rose-500/20";
    if (score > 60) return "text-orange-500 bg-orange-500/10 border-orange-500/20";
    if (score > 35) return "text-amber-500 bg-amber-500/10 border-amber-500/20";
    return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
  };

  if (authLoading || !isAuthenticated) {
    return (
      <div className="h-[60vh] flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary border-r-2" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center border-b border-border pb-6">
        <div>
          <h1 className="text-3xl font-black tracking-tight">Threat Logs & Archives</h1>
          <p className="text-xs text-muted-foreground mt-1">
            Browse and query prior static binary scan reports.
          </p>
        </div>
      </div>

      <AnimatePresence mode="wait">
        {!selectedScan ? (
          // LIST VIEW
          <motion.div
            key="list"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="space-y-6"
          >
            {/* Search and Filters Toolbar */}
            <form onSubmit={handleSearchSubmit} className="flex flex-col md:flex-row gap-4 bg-secondary/20 p-4 border border-border rounded-xl glass-panel">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={16} />
                <Input
                  placeholder="Query scan by filename or cryptographic hash..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-10 border-border bg-black/20"
                />
              </div>
              <div className="flex gap-2 flex-wrap">
                <div className="flex items-center gap-2 border border-border rounded-md px-3 bg-black/20">
                  <Filter size={14} className="text-muted-foreground" />
                  <select
                    value={selectedFilter}
                    onChange={(e) => setSelectedFilter(e.target.value)}
                    className="bg-transparent border-0 text-sm focus:outline-none text-muted-foreground py-2 cursor-pointer font-medium"
                  >
                    {CLASSES.map((cls) => (
                      <option key={cls} value={cls} className="bg-slate-950 text-foreground">
                        {cls}
                      </option>
                    ))}
                  </select>
                </div>
                <Button type="submit" className="glow-blue">
                  Search
                </Button>
              </div>
            </form>

            {loading ? (
              // Table Skeleton Loader
              <Card className="shimmer h-[400px] w-full" />
            ) : scans.length === 0 ? (
              <Card className="border border-border p-12 text-center flex flex-col items-center justify-center">
                <FileCode size={48} className="text-muted-foreground mb-3 animate-pulse" />
                <h3 className="text-base font-bold mb-1">No Scans Found</h3>
                <p className="text-sm text-muted-foreground max-w-sm">
                  We couldn't find any scan logs matching your search parameters. Try adjusting your query filters or scan a new file.
                </p>
                <Button className="mt-6 glow-blue" onClick={() => router.push("/scan")}>
                  Scan New Binary
                </Button>
              </Card>
            ) : (
              // Scans Table List
              <Card className="overflow-hidden border border-border shadow-xl">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-sm">
                    <thead>
                      <tr className="border-b border-border text-xs text-muted-foreground font-semibold uppercase bg-secondary/10">
                        <th className="py-4 px-6">Filename</th>
                        <th className="py-4 px-6">Family</th>
                        <th className="py-4 px-6">Threat Score</th>
                        <th className="py-4 px-6">Scan Date</th>
                        <th className="py-4 px-6 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {scans.map((scan) => (
                        <tr 
                          key={scan.id} 
                          onClick={() => setSelectedScan(scan)}
                          className="hover:bg-secondary/20 transition-colors cursor-pointer group"
                        >
                          <td className="py-4 px-6 max-w-xs md:max-w-md">
                            <span className="font-semibold block truncate group-hover:text-primary transition-colors">
                              {scan.filename}
                            </span>
                            <span className="text-[10px] font-mono text-muted-foreground block mt-0.5 max-w-[200px] truncate">
                              SHA256: {scan.sha256}
                            </span>
                          </td>
                          <td className="py-4 px-6">
                            <span className="text-xs font-semibold px-2.5 py-0.5 rounded bg-secondary text-foreground border border-border">
                              {scan.prediction}
                            </span>
                          </td>
                          <td className="py-4 px-6">
                            <span className={`text-xs font-bold px-2 py-0.5 rounded border ${getScoreColor(scan.threat_score)}`}>
                              {scan.threat_score}/100
                            </span>
                          </td>
                          <td className="py-4 px-6 text-muted-foreground text-xs font-medium">
                            <span className="flex items-center gap-1.5">
                              <Calendar size={12} />
                              {new Date(scan.created_at).toLocaleDateString()}
                            </span>
                          </td>
                          <td className="py-4 px-6 text-right" onClick={(e) => e.stopPropagation()}>
                            <div className="flex gap-2 justify-end">
                              <Button 
                                variant="ghost" 
                                size="icon" 
                                onClick={() => setSelectedScan(scan)}
                                title="View detailed report"
                              >
                                <Eye size={16} />
                              </Button>
                              <Button 
                                variant="ghost" 
                                size="icon" 
                                className="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10"
                                onClick={(e) => handleDelete(e, scan.id)}
                                disabled={deletingId === scan.id}
                                title="Delete record"
                              >
                                {deletingId === scan.id ? (
                                  <RefreshCw size={14} className="animate-spin" />
                                ) : (
                                  <Trash2 size={16} />
                                )}
                              </Button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}
          </motion.div>
        ) : (
          // DETAILED AUDIT VIEW
          <motion.div
            key="details"
            initial={{ opacity: 0, scale: 0.99 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.99 }}
            className="grid grid-cols-1 lg:grid-cols-4 gap-6"
          >
            {/* Left Column: Risk gauge sticky */}
            <div className="lg:col-span-1">
              <Card className="h-fit sticky top-6">
                <CardHeader className="text-center border-b border-border pb-4 flex flex-row items-center justify-between">
                  <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                    Threat Score
                  </CardTitle>
                  <Button variant="ghost" size="icon" onClick={() => setSelectedScan(null)} className="h-6 w-6">
                    <X size={16} />
                  </Button>
                </CardHeader>
                <CardContent className="p-0">
                  <RiskGauge score={selectedScan.threat_score} prediction={selectedScan.prediction} />
                  <div className="px-6 pb-6 pt-2 space-y-4 border-t border-border/40 mt-2 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground font-semibold">CLASSIFIED FAMILY</span>
                      <span className="font-bold text-foreground">{selectedScan.prediction}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground font-semibold">CONFIDENCE</span>
                      <span className="font-bold text-foreground">{(selectedScan.confidence_score * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Right Column: Full details */}
            <div className="lg:col-span-3">
              <StaticReport record={selectedScan} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
