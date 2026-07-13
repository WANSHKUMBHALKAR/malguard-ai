"use client";

import React, { useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/hooks/use-auth";
import { Shield, ShieldAlert, Cpu, Layers, Activity, ChevronRight } from "lucide-react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";

export default function Home() {
  const router = useRouter();
  const { isAuthenticated, loading } = useAuth();

  useEffect(() => {
    if (!loading && isAuthenticated) {
      router.push("/dashboard");
    }
  }, [isAuthenticated, loading, router]);

  if (loading || isAuthenticated) {
    return (
      <div className="h-[70vh] flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-primary border-r-2" />
      </div>
    );
  }

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: { y: 0, opacity: 1 }
  };

  return (
    <motion.div 
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="flex flex-col items-center justify-center min-h-[80vh] text-center max-w-4xl mx-auto px-4"
    >
      {/* Glow Header badge */}
      <motion.div 
        variants={itemVariants}
        className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full border border-primary/20 bg-primary/10 text-xs font-semibold text-primary mb-6 animate-pulse"
      >
        <Shield size={12} />
        Production-Ready Static Analysis Engine
      </motion.div>

      {/* Main Hero Header */}
      <motion.h1 
        variants={itemVariants}
        className="text-4xl md:text-6xl font-black tracking-tight leading-none mb-6 text-foreground"
      >
        AI-Powered Windows PE <br />
        <span className="bg-gradient-to-r from-primary via-blue-400 to-indigo-400 bg-clip-text text-transparent">
          Malware Forensics Platform
        </span>
      </motion.h1>

      {/* Description */}
      <motion.p 
        variants={itemVariants}
        className="text-lg text-muted-foreground max-w-2xl mb-8 leading-relaxed"
      >
        Analyze Portable Executable binaries (.exe, .dll, .sys) statically using machine learning classifiers. Extract raw features, calculate Shannon entropy, map to MITRE ATT&CK techniques, and export detailed forensic reports.
      </motion.p>

      {/* Actions */}
      <motion.div 
        variants={itemVariants}
        className="flex gap-4 flex-wrap justify-center mb-16"
      >
        <Link href="/login">
          <Button variant="default" size="lg" className="px-8 font-semibold glow-blue">
            Access Dashboard
            <ChevronRight size={16} className="ml-1" />
          </Button>
        </Link>
        <Link href="/register">
          <Button variant="outline" size="lg" className="px-8 font-semibold">
            Create Account
          </Button>
        </Link>
      </motion.div>

      {/* Core Highlights Grid */}
      <motion.div 
        variants={itemVariants}
        className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full text-left"
      >
        <div className="p-6 rounded-xl border border-border bg-card/50 backdrop-blur-md glass-panel glass-panel-hover">
          <div className="p-3 w-fit rounded-lg bg-primary/10 border border-primary/20 text-primary mb-4">
            <Cpu size={24} />
          </div>
          <h3 className="text-lg font-bold mb-2">Multiclass Classifiers</h3>
          <p className="text-sm text-muted-foreground">
            Classifies binaries into Benign or 9 target malware families including Ransomware, Trojans, Botnets, and Backdoors.
          </p>
        </div>

        <div className="p-6 rounded-xl border border-border bg-card/50 backdrop-blur-md glass-panel glass-panel-hover">
          <div className="p-3 w-fit rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 mb-4">
            <Layers size={24} />
          </div>
          <h3 className="text-lg font-bold mb-2">Deep Static Extractor</h3>
          <p className="text-sm text-muted-foreground">
            Parses PE sections, imported DLL libraries, and API calls using pefile to generate Shannon entropy models.
          </p>
        </div>

        <div className="p-6 rounded-xl border border-border bg-card/50 backdrop-blur-md glass-panel glass-panel-hover">
          <div className="p-3 w-fit rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 mb-4">
            <ShieldAlert size={24} />
          </div>
          <h3 className="text-lg font-bold mb-2">Explainable AI (XAI)</h3>
          <p className="text-sm text-muted-foreground">
            Visualizes which exact static header variables contributed most to the model classification output.
          </p>
        </div>
      </motion.div>
    </motion.div>
  );
}
