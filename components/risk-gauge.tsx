"use client";

import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";

interface RiskGaugeProps {
  score: number;
  prediction: string;
}

export function RiskGauge({ score, prediction }: RiskGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Animate the score counter on mount
    let start = 0;
    const duration = 1000;
    const increment = score / (duration / 16);
    
    const timer = setInterval(() => {
      start += increment;
      if (start >= score) {
        clearInterval(timer);
        setAnimatedScore(score);
      } else {
        setAnimatedScore(Math.floor(start));
      }
    }, 16);

    return () => clearInterval(timer);
  }, [score]);

  // Determine colors based on threat score
  let strokeColor = "#10b981"; // Emerald (Clean)
  let shadowClass = "glow-emerald";
  let labelText = "CLEAN / BENIGN";

  if (score > 85) {
    strokeColor = "#ef4444"; // Red (Critical)
    shadowClass = "glow-rose";
    labelText = `CRITICAL: ${prediction.toUpperCase()}`;
  } else if (score > 60) {
    strokeColor = "#f97316"; // Orange (High)
    shadowClass = "glow-amber";
    labelText = `HIGH: ${prediction.toUpperCase()}`;
  } else if (score > 35) {
    strokeColor = "#f59e0b"; // Amber (Medium)
    shadowClass = "glow-amber";
    labelText = `WARNING: ${prediction.toUpperCase()}`;
  } else if (score > 10) {
    strokeColor = "#84cc16"; // Lime (Low)
    shadowClass = "glow-blue";
    labelText = `LOW: ${prediction.toUpperCase()}`;
  }

  // Circular progress calculations
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center p-6">
      <div className="relative w-56 h-56 flex items-center justify-center">
        {/* Outer Glow Ring */}
        <div className={`absolute inset-0 rounded-full border border-dashed border-white/5 animate-spin [animation-duration:120s]`} />
        
        {/* Main Gauge SVG */}
        <svg className="w-48 h-48 transform -rotate-90">
          {/* Background circle */}
          <circle
            cx="96"
            cy="96"
            r={radius}
            fill="transparent"
            stroke="rgba(255, 255, 255, 0.03)"
            strokeWidth="10"
          />
          {/* Foreground progress circle */}
          <motion.circle
            cx="96"
            cy="96"
            r={radius}
            fill="transparent"
            stroke={strokeColor}
            strokeWidth="10"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset }}
            transition={{ duration: 1.2, ease: "easeOut" }}
            strokeLinecap="round"
            style={{
              filter: `drop-shadow(0 0 8px ${strokeColor}40)`
            }}
          />
        </svg>

        {/* Inner Centered Metrics */}
        <div className="absolute flex flex-col items-center justify-center">
          <span className="text-5xl font-black tracking-tighter text-foreground bg-gradient-to-b from-white to-slate-400 bg-clip-text text-transparent">
            {animatedScore}
          </span>
          <span className="text-[10px] tracking-widest text-muted-foreground uppercase mt-1 font-semibold">
            THREAT SCORE
          </span>
        </div>
      </div>

      {/* Label Info Card */}
      <motion.div 
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className={`mt-4 px-4 py-1.5 rounded-full border text-xs font-bold text-center bg-black/40 ${shadowClass}`}
      >
        <span style={{ color: strokeColor }}>{labelText}</span>
      </motion.div>
    </div>
  );
}
