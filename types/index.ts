export interface User {
  id: string;
  email: string;
  role: string;
  created_at: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  category: string;
}

export interface SectionDetails {
  name: string;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  is_writable: boolean;
  is_executable: boolean;
  suspicious: boolean;
}

export interface IOCSummary {
  sha256: string;
  md5: string;
  high_risk_apis_identified: number;
  suspicious_sections_count: number;
}

export interface VirusTotalData {
  harmless: number;
  suspicious: number;
  malicious: number;
  undetected: number;
  permalink: string;
  status: string;
  message?: string;
}

export interface ScanRecord {
  id: string;
  user_id: string;
  filename: string;
  file_size: number;
  sha256: string;
  md5: string;
  entropy: number;
  num_sections: number;
  compile_timestamp: string | null;
  prediction: string;
  threat_score: number;
  confidence_score: number;
  mitre_mapping: MitreTechnique[];
  ioc_summary: IOCSummary;
  suspicious_apis: string[];
  imported_dlls: string[];
  entropy_analysis: Record<string, number>;
  section_analysis: SectionDetails[];
  recommended_mitigations: string[];
  feature_importance: Record<string, number>;
  virustotal_data?: VirusTotalData | null;
  created_at: string;
}

export interface AnalyticsSummary {
  total_scans: number;
  average_risk_score: number;
  malware_family_distribution: Record<string, number>;
  threat_level_distribution: {
    Clean: number;
    Low: number;
    Medium: number;
    High: number;
    Critical: number;
  };
  timeline: {
    date: string;
    scans: number;
    malicious: number;
  }[];
}
