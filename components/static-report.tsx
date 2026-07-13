"use client";

import React, { useState } from "react";
import { ScanRecord } from "@/types";
import { api } from "@/lib/api";
import { 
  FileCode, 
  Hash, 
  Layers, 
  ShieldAlert, 
  Activity, 
  Download, 
  Info, 
  ExternalLink,
  Cpu,
  Clock,
  Sparkles
} from "lucide-react";
import { motion } from "framer-motion";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface StaticReportProps {
  record: ScanRecord;
}

export function StaticReport({ record }: StaticReportProps) {
  const [exporting, setExporting] = useState<string | null>(null);

  const handleExport = async (format: "pdf" | "json" | "csv") => {
    setExporting(format);
    try {
      await api.downloadReport(record.id, format);
    } catch (err) {
      alert("Failed to export report.");
    } finally {
      setExporting(null);
    }
  };

  const getThreatColor = (score: number) => {
    if (score > 85) return "text-rose-500 border-rose-500/20 bg-rose-500/5";
    if (score > 60) return "text-orange-500 border-orange-500/20 bg-orange-500/5";
    if (score > 35) return "text-amber-500 border-amber-500/20 bg-amber-500/5";
    return "text-emerald-500 border-emerald-500/20 bg-emerald-500/5";
  };

  return (
    <div className="space-y-6">
      {/* Quick Info & Export Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-border pb-6">
        <div>
          <h2 className="text-xl font-extrabold flex items-center gap-2">
            <FileCode className="text-primary" />
            Analysis Report: <span className="text-muted-foreground font-normal">{record.filename}</span>
          </h2>
          <p className="text-xs text-muted-foreground mt-1">
            Scan ID: {record.id} • Processed on {new Date(record.created_at).toLocaleString()}
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => handleExport("json")}
            disabled={exporting !== null}
          >
            <Download size={14} className="mr-1.5" />
            {exporting === "json" ? "Exporting..." : "JSON"}
          </Button>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => handleExport("csv")}
            disabled={exporting !== null}
          >
            <Download size={14} className="mr-1.5" />
            {exporting === "csv" ? "Exporting..." : "CSV"}
          </Button>
          <Button 
            variant="default" 
            size="sm" 
            onClick={() => handleExport("pdf")}
            disabled={exporting !== null}
            className="glow-blue"
          >
            <Download size={14} className="mr-1.5" />
            {exporting === "pdf" ? "Exporting..." : "PDF Report"}
          </Button>
        </div>
      </div>

      {/* Grid: Hashes & Explainable AI */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Hashes Column */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
              <Hash size={16} />
              Checksums & Signatures
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm">
            <div>
              <span className="text-xs text-muted-foreground block font-semibold mb-0.5">SHA256</span>
              <code className="text-xs font-mono bg-black/40 px-2 py-1 rounded block overflow-x-auto text-primary">
                {record.sha256}
              </code>
            </div>
            <div>
              <span className="text-xs text-muted-foreground block font-semibold mb-0.5">MD5</span>
              <code className="text-xs font-mono bg-black/40 px-2 py-1 rounded block overflow-x-auto text-primary">
                {record.md5}
              </code>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-xs text-muted-foreground block font-semibold mb-0.5">File Size</span>
                <span className="font-semibold">{(record.file_size / 1024).toFixed(2)} KB</span>
              </div>
              <div>
                <span className="text-xs text-muted-foreground block font-semibold mb-0.5">PE Sections</span>
                <span className="font-semibold">{record.num_sections} sections</span>
              </div>
              <div>
                <span className="text-xs text-muted-foreground block font-semibold mb-0.5">Compile Date</span>
                <span className="font-semibold text-xs flex items-center gap-1">
                  <Clock size={12} className="text-primary" />
                  {record.compile_timestamp ? new Date(record.compile_timestamp).toLocaleDateString() : "N/A"}
                </span>
              </div>
              <div>
                <span className="text-xs text-muted-foreground block font-semibold mb-0.5">File Entropy</span>
                <span className="font-semibold">{record.entropy.toFixed(4)}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Explainable AI (Feature Importance) */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
              <Sparkles size={16} className="text-indigo-400" />
              Explainable AI (Feature Importance)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-xs text-muted-foreground">
              Calculates the relative contribution of each static signature in predicting the threat level.
            </p>
            <div className="space-y-3 pt-2">
              {Object.entries(record.feature_importance)
                .sort((a, b) => b[1] - a[1])
                .map(([feature, importance]) => (
                  <div key={feature} className="space-y-1">
                    <div className="flex justify-between text-xs font-medium">
                      <span className="font-mono text-muted-foreground capitalize">
                        {feature.replace(/_/g, " ")}
                      </span>
                      <span>{importance}%</span>
                    </div>
                    <div className="w-full bg-secondary/40 h-2 rounded-full overflow-hidden border border-border">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${importance}%` }}
                        transition={{ duration: 1, ease: "easeOut" }}
                        className="bg-gradient-to-r from-primary to-indigo-500 h-full rounded-full"
                      />
                    </div>
                  </div>
                ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sections Analysis */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
            <Layers size={16} />
            PE Sections Registry
          </CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-muted-foreground font-semibold uppercase">
                <th className="py-3 px-4">Section</th>
                <th className="py-3 px-4">Raw Size</th>
                <th className="py-3 px-4">Entropy</th>
                <th className="py-3 px-4">Permissions</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {record.section_analysis.map((sec, idx) => (
                <tr key={idx} className="hover:bg-secondary/20 transition-colors">
                  <td className="py-3 px-4 font-mono font-bold text-foreground">
                    {sec.name || "(Anonymous)"}
                  </td>
                  <td className="py-3 px-4 font-mono text-xs">
                    {sec.raw_size.toLocaleString()} B
                  </td>
                  <td className="py-3 px-4 font-mono text-xs">
                    {sec.entropy.toFixed(4)}
                  </td>
                  <td className="py-3 px-4 text-xs font-semibold">
                    <span className="flex gap-1.5">
                      <span className="px-1.5 py-0.5 rounded bg-secondary text-muted-foreground">R</span>
                      {sec.is_writable && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                          W
                        </span>
                      )}
                      {sec.is_executable && (
                        <span className="px-1.5 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                          X
                        </span>
                      )}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {sec.suspicious ? (
                      <span className="text-[10px] uppercase font-bold text-rose-400 bg-rose-500/10 px-2 py-0.5 rounded-full border border-rose-500/20">
                        Suspicious Flags
                      </span>
                    ) : (
                      <span className="text-[10px] uppercase font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-full border border-emerald-500/20">
                        Normal
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {/* Grid: MITRE ATT&CK & Mitigations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* MITRE Panel */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
              <ShieldAlert size={16} />
              MITRE ATT&CK Mapping
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {record.mitre_mapping.length === 0 ? (
              <div className="flex flex-col items-center justify-center p-6 text-center border border-dashed border-border rounded-lg">
                <Info className="text-muted-foreground mb-2" size={24} />
                <p className="text-xs text-muted-foreground">
                  No dynamic MITRE ATT&CK techniques mapped to static executable structures.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {record.mitre_mapping.map((tech, idx) => (
                  <div key={idx} className="p-3 bg-secondary/30 border border-border rounded-lg flex items-start justify-between">
                    <div>
                      <span className="text-xs font-mono font-bold text-primary block">
                        {tech.id}
                      </span>
                      <span className="text-sm font-semibold text-foreground">
                        {tech.name}
                      </span>
                      <span className="text-[10px] text-muted-foreground block mt-0.5">
                        Category: {tech.category}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Recommended Actions */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
              <Cpu size={16} />
              Recommended Incident Actions
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {record.recommended_mitigations.map((mit, idx) => (
              <div key={idx} className="flex gap-3 items-start text-sm">
                <span className="flex-shrink-0 w-5 h-5 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-xs font-bold text-primary mt-0.5">
                  {idx + 1}
                </span>
                <span className="text-muted-foreground">{mit}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* suspicious APIs & DLL Imports */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Suspicious APIs */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
              <Activity size={16} className="text-amber-400" />
              High-Risk API Call Imports
            </CardTitle>
          </CardHeader>
          <CardContent>
            {record.suspicious_apis.length === 0 ? (
              <p className="text-xs text-muted-foreground italic">
                No high-risk API imports match malware footprint signatures.
              </p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {record.suspicious_apis.map((api, idx) => (
                  <span 
                    key={idx}
                    className="font-mono text-xs px-2.5 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20"
                  >
                    {api}
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* DLL Imports */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-muted-foreground">
              <Layers size={16} />
              Imported Dynamic Libraries (DLLs)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-1.5">
              {record.imported_dlls.map((dll, idx) => (
                <span 
                  key={idx}
                  className="font-mono text-xs px-2 py-1 rounded bg-secondary text-muted-foreground border border-border"
                >
                  {dll}
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* VirusTotal Enrichment Section */}
      {record.virustotal_data && (
        <Card className="border border-indigo-500/10 shadow-lg shadow-indigo-500/5">
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-sm font-bold uppercase tracking-wider text-muted-foreground">
              <span className="flex items-center gap-2">
                <Sparkles size={16} className="text-indigo-400" />
                VirusTotal Global Multi-Engine Intelligence
              </span>
              {record.virustotal_data.status === "found" && (
                <a 
                  href={record.virustotal_data.permalink} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-xs text-primary flex items-center gap-1 hover:underline font-semibold"
                >
                  View Full VT Page
                  <ExternalLink size={12} />
                </a>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {record.virustotal_data.status === "found" ? (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                <div className="p-3 bg-rose-500/5 border border-rose-500/20 rounded-lg">
                  <span className="block text-2xl font-black text-rose-500">
                    {record.virustotal_data.malicious}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Malicious</span>
                </div>
                <div className="p-3 bg-amber-500/5 border border-amber-500/20 rounded-lg">
                  <span className="block text-2xl font-black text-amber-500">
                    {record.virustotal_data.suspicious}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Suspicious</span>
                </div>
                <div className="p-3 bg-emerald-500/5 border border-emerald-500/20 rounded-lg">
                  <span className="block text-2xl font-black text-emerald-400">
                    {record.virustotal_data.harmless}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Harmless</span>
                </div>
                <div className="p-3 bg-secondary/40 border border-border rounded-lg">
                  <span className="block text-2xl font-black text-muted-foreground">
                    {record.virustotal_data.undetected}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-semibold uppercase">Undetected</span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">
                {record.virustotal_data.message || "File hash not catalogued in VirusTotal database."}
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
