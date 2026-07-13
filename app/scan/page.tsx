"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { api } from "@/lib/api";
import { ScanRecord } from "@/types";
import { 
  UploadCloud, 
  FileCode, 
  ShieldAlert, 
  RefreshCw, 
  ArrowLeft,
  Info,
  CheckCircle,
  FileWarning
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { RiskGauge } from "@/components/risk-gauge";
import { StaticReport } from "@/components/static-report";

export default function ScanPage() {
  const router = useRouter();
  const { isAuthenticated, loading: authLoading } = useAuth();
  
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState("");
  const [result, setResult] = useState<ScanRecord | null>(null);
  
  const [isDragActive, setIsDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!authLoading && !isAuthenticated) {
      router.push("/login");
    }
  }, [isAuthenticated, authLoading, router]);

  if (authLoading || !isAuthenticated) {
    return (
      <div className="h-[60vh] flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary border-r-2" />
      </div>
    );
  }

  const validateFile = (selectedFile: File): boolean => {
    setScanError("");
    
    // Validate File Extension (.exe, .dll, .sys)
    const allowedExtensions = [".exe", ".dll", ".sys"];
    const fileName = selectedFile.name.toLowerCase();
    const hasValidExt = allowedExtensions.some(ext => fileName.endsWith(ext));
    
    if (!hasValidExt) {
      setScanError("Invalid file type. Only Windows Executables (.exe, .dll, .sys) are supported.");
      return false;
    }

    // Validate File Size (max 25MB)
    const maxBytes = 25 * 1024 * 1024;
    if (selectedFile.size > maxBytes) {
      setScanError("File exceeds the maximum upload limit of 25 MB.");
      return false;
    }

    return true;
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setIsDragActive(true);
    } else if (e.type === "dragleave") {
      setIsDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const selectedFile = e.dataTransfer.files[0];
      if (validateFile(selectedFile)) {
        setFile(selectedFile);
      }
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      if (validateFile(selectedFile)) {
        setFile(selectedFile);
      }
    }
  };

  const handleBrowse = () => {
    fileInputRef.current?.click();
  };

  const runAnalysis = async () => {
    if (!file) return;
    setScanning(true);
    setScanError("");
    
    try {
      const scanRecord = await api.scanFile(file);
      setResult(scanRecord);
    } catch (err: any) {
      setScanError(err.message || "An unexpected error occurred during analysis.");
    } finally {
      setScanning(false);
    }
  };

  const resetScanner = () => {
    setFile(null);
    setResult(null);
    setScanError("");
  };

  return (
    <div className="space-y-6">
      {/* Top Navigation scan page header */}
      <div className="flex justify-between items-center border-b border-border pb-6">
        <div className="flex items-center gap-3">
          {result && (
            <Button variant="ghost" size="icon" onClick={resetScanner}>
              <ArrowLeft size={18} />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-black tracking-tight">PE File Analyzer</h1>
            <p className="text-xs text-muted-foreground mt-1">
              Static analysis, signature matching, and machine learning threat prediction workstation.
            </p>
          </div>
        </div>
      </div>

      <AnimatePresence mode="wait">
        {!result ? (
          // UPLOADER WORKSPACE
          <motion.div
            key="uploader"
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -15 }}
            className="max-w-2xl mx-auto"
          >
            <Card className="border border-border shadow-xl">
              <CardHeader>
                <CardTitle className="text-lg font-bold">Select File for Forensic Audit</CardTitle>
                <CardDescription>
                  Upload Windows Portable Executable files to run heuristics. Files are analyzed strictly in memory.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Drag and Drop Zone */}
                <div
                  onDragEnter={handleDrag}
                  onDragOver={handleDrag}
                  onDragLeave={handleDrag}
                  onDrop={handleDrop}
                  className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center cursor-pointer transition-all duration-300 ${
                    isDragActive 
                      ? "border-primary bg-primary/5 glow-blueScale scale-[0.99]" 
                      : "border-border bg-black/20 hover:bg-secondary/20 hover:border-muted-foreground"
                  }`}
                  onClick={handleBrowse}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    className="hidden"
                    onChange={handleFileChange}
                    accept=".exe,.dll,.sys"
                  />
                  <UploadCloud size={48} className={`mb-4 transition-transform duration-300 ${
                    isDragActive ? "text-primary scale-110" : "text-muted-foreground"
                  }`} />
                  
                  {file ? (
                    <div className="text-center">
                      <span className="font-bold text-sm block max-w-xs truncate text-foreground mb-1">
                        {file.name}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {(file.size / 1024).toFixed(2)} KB
                      </span>
                    </div>
                  ) : (
                    <div className="text-center space-y-1">
                      <p className="text-sm font-semibold">Drag & Drop file here, or click to browse</p>
                      <p className="text-xs text-muted-foreground">Supports .exe, .dll, and .sys up to 25 MB</p>
                    </div>
                  )}
                </div>

                {/* Error Banner */}
                {scanError && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    className="p-4 rounded-xl border border-rose-500/20 bg-rose-500/10 text-rose-400 text-xs font-semibold flex items-start gap-2.5"
                  >
                    <FileWarning size={16} className="flex-shrink-0 mt-0.5" />
                    <div className="space-y-1">
                      <p className="font-bold uppercase tracking-wider text-[10px]">Security / Validation Error</p>
                      <p>{scanError}</p>
                    </div>
                  </motion.div>
                )}

                {/* Submit Actions */}
                {file && (
                  <div className="flex gap-3 justify-end pt-2">
                    <Button variant="outline" onClick={resetScanner} disabled={scanning}>
                      Clear Selection
                    </Button>
                    <Button onClick={runAnalysis} className="glow-blue" disabled={scanning}>
                      {scanning ? (
                        <>
                          <RefreshCw size={14} className="animate-spin mr-2" />
                          Running Forensic Extraction...
                        </>
                      ) : (
                        "Analyze Binary"
                      )}
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ) : (
          // RESULTS WORKSPACE
          <motion.div
            key="results"
            initial={{ opacity: 0, scale: 0.98 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.98 }}
            className="grid grid-cols-1 lg:grid-cols-4 gap-6"
          >
            {/* Left Column: Risk gauge */}
            <div className="lg:col-span-1">
              <Card className="h-fit sticky top-6">
                <CardHeader className="text-center border-b border-border pb-4">
                  <CardTitle className="text-sm font-bold uppercase tracking-wider text-muted-foreground">
                    Threat Assessment
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <RiskGauge score={result.threat_score} prediction={result.prediction} />
                  
                  <div className="px-6 pb-6 pt-2 space-y-4 border-t border-border/40 mt-2 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground font-semibold">CLASSIFIED FAMILY</span>
                      <span className="font-bold text-foreground">{result.prediction}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground font-semibold">CLASSIFICATION PROBABILITY</span>
                      <span className="font-bold text-foreground">{(result.confidence_score * 100).toFixed(1)}%</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Right Column: Static analysis lists */}
            <div className="lg:col-span-3">
              <StaticReport record={result} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
