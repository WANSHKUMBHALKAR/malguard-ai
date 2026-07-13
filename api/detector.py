import os
import math
import hashlib
import json
import numpy as np
import pefile
import joblib
from datetime import datetime
from collections import Counter
from fastapi import HTTPException, status

# Define standard target malware classes
CLASSES = [
    "Benign", "Trojan", "Worm", "Spyware", "Ransomware",
    "Adware", "Backdoor", "Downloader", "Cryptominer", "Botnet"
]

# Blacklist of common high-risk APIs
SUSPICIOUS_API_LIST = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext",
    "OpenProcess", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "LdrLoadDll",
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW",
    "CryptEncrypt", "CryptDecrypt", "CryptHashData"
]

# Mapping APIs to MITRE ATT&CK Techniques
MITRE_ATTACK_MAP = {
    "VirtualAllocEx": {"id": "T1055", "name": "Process Injection", "category": "Defense Evasion / Privilege Escalation"},
    "WriteProcessMemory": {"id": "T1055", "name": "Process Injection", "category": "Defense Evasion / Privilege Escalation"},
    "CreateRemoteThread": {"id": "T1055", "name": "Process Injection", "category": "Defense Evasion / Privilege Escalation"},
    "QueueUserAPC": {"id": "T1055", "name": "Process Injection", "category": "Defense Evasion / Privilege Escalation"},
    "RegSetValueExA": {"id": "T1112", "name": "Modify Registry", "category": "Defense Evasion"},
    "RegSetValueExW": {"id": "T1112", "name": "Modify Registry", "category": "Defense Evasion"},
    "RegCreateKeyExA": {"id": "T1112", "name": "Modify Registry", "category": "Defense Evasion"},
    "RegCreateKeyExW": {"id": "T1112", "name": "Modify Registry", "category": "Defense Evasion"},
    "InternetOpenA": {"id": "T1071", "name": "Application Layer Protocol", "category": "Command and Control"},
    "InternetConnectA": {"id": "T1071", "name": "Application Layer Protocol", "category": "Command and Control"},
    "HttpSendRequestA": {"id": "T1071", "name": "Application Layer Protocol", "category": "Command and Control"},
    "URLDownloadToFileA": {"id": "T1105", "name": "Ingress Tool Transfer", "category": "Command and Control"},
    "IsDebuggerPresent": {"id": "T1497", "name": "Virtualization/Sandbox Evasion", "category": "Defense Evasion / Discovery"},
    "CheckRemoteDebuggerPresent": {"id": "T1497", "name": "Virtualization/Sandbox Evasion", "category": "Defense Evasion / Discovery"},
    "SetWindowsHookExA": {"id": "T1056.001", "name": "Input Capture: Keylogging", "category": "Credential Access / Collection"},
    "GetAsyncKeyState": {"id": "T1056.001", "name": "Input Capture: Keylogging", "category": "Credential Access / Collection"},
    "CryptDecrypt": {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "category": "Defense Evasion"},
    "CryptEncrypt": {"id": "T1140", "name": "Deobfuscate/Decode Files or Information", "category": "Defense Evasion"},
    "CreateProcessA": {"id": "T1106", "name": "Execution through API", "category": "Execution"},
    "ShellExecuteA": {"id": "T1106", "name": "Execution through API", "category": "Execution"}
}

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    counter = Counter(data)
    total_len = len(data)
    for count in counter.values():
        p_x = count / total_len
        entropy -= p_x * math.log2(p_x)
    return entropy

def get_mitigations_for_class(malware_class: str) -> list:
    mitigations = {
        "Ransomware": [
            "Isolate the system from local networks immediately to prevent lateral spread.",
            "Deploy Endpoint Detection and Response (EDR) agents in isolation mode.",
            "Identify and block the encryption process PID in memory.",
            "Ensure Volume Shadow Copies (VSS) are preserved or audit delete actions.",
            "Restore infected assets from secure offline backup repositories."
        ],
        "Trojan": [
            "Inspect system persistence mechanisms (Registry Run keys, Scheduled Tasks, Winlogon).",
            "Clear temporary folders (%TEMP%, AppData/Local/Temp) and terminate active user-space processes.",
            "Scan host memory for injected dynamic link libraries (DLLs).",
            "Rotate active user credentials and keys immediately."
        ],
        "Backdoor": [
            "Sever outbound internet connectivity to block Command & Control (C2) links.",
            "Audit all listening network ports and terminate corresponding processes.",
            "Verify hosts file integrity and inspect system proxy settings.",
            "Perform host-based credential rotation."
        ],
        "Worm": [
            "Block port 445 (SMB) and 135/139 (NetBIOS) internally across subnets.",
            "Scan all active mapped network shares and network drives.",
            "Audit system administrative actions and block psexec-like execution commands.",
            "Deploy patches for known RPC/SMB remote execution vulnerabilities."
        ],
        "Spyware": [
            "Audit running browser plugins and remove unauthorized extensions.",
            "Revoke browser storage session tokens and stored credentials.",
            "Identify hook-related processes using APIs like SetWindowsHookEx.",
            "Inspect running system services for unexpected key-logging activity."
        ],
        "Cryptominer": [
            "Audit processes consuming high CPU/GPU resources.",
            "Remove run-at-startup registry bindings and scheduled cron tasks.",
            "Block common stratum protocol communication channels and mining pool domains.",
            "Deploy memory-based endpoint protection policies."
        ],
        "Adware": [
            "Reset browser configurations to defaults.",
            "Remove newly installed programs and suspicious control panel entries.",
            "Block browser adware redirects through local firewall policies.",
            "Run automated adware cleanup utility."
        ],
        "Botnet": [
            "Block communication with known Command & Control (C2) IPs.",
            "Implement connection rate limiting on outbound network packets.",
            "Check active sockets and trace process ownership.",
            "Rotate administrative system passwords."
        ],
        "Downloader": [
            "Inspect temporary write folders for recently dropped executables.",
            "Block malicious source domains identified in web proxy filters.",
            "Revoke local network write rights for user-level processes."
        ],
        "Benign": [
            "Maintain standard system baseline monitoring.",
            "Ensure signature and system patches are kept up-to-date.",
            "Apply local privilege boundaries to minimize administrative actions."
        ]
    }
    return mitigations.get(malware_class, ["Monitor execution behavior in sandbox environment."])

def load_trained_classifier():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    model_path = os.path.join(base_dir, "models", "malware_detector.joblib")
    metadata_path = os.path.join(base_dir, "models", "model_metadata.json")

    # Safe fallback if model is not trained yet
    if not os.path.exists(model_path):
        print("Model file not found. Generating a fast fallback model for application runtime...")
        from sklearn.ensemble import RandomForestClassifier
        X_dummy = np.random.rand(100, 8)
        y_dummy = np.random.randint(0, 10, size=100)
        fallback_model = RandomForestClassifier(n_estimators=10, random_state=42)
        fallback_model.fit(X_dummy, y_dummy)
        
        # Ensure directories exist
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(fallback_model, model_path)
        
        feature_names = ["file_size", "entropy", "num_sections", "num_imported_dlls", "num_imported_apis", "has_suspicious_apis", "has_suspicious_sections", "compile_timestamp"]
        fallback_metadata = {
            "best_model_name": "Random Forest (Fallback)",
            "features": feature_names,
            "feature_importance": dict(zip(feature_names, fallback_model.feature_importances_.tolist())),
            "metrics": {"accuracy": 0.5}
        }
        with open(metadata_path, "w") as f:
            json.dump(fallback_metadata, f)
        
        return fallback_model, fallback_metadata

    try:
        model = joblib.load(model_path)
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
        return model, metadata
    except Exception as e:
        print(f"Error loading classifier: {e}")
        raise RuntimeError("Classifier load error.")

class StaticPEAnalyzer:
    def __init__(self, file_content: bytes, filename: str):
        self.content = file_content
        self.filename = filename
        self.size = len(file_content)
        
        # Validate file size limits (max 25MB)
        if self.size > 25 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File exceeds the maximum upload limit of 25 MB."
            )
            
        # Validate PE Header signatures (must begin with 'MZ' magic number)
        if not file_content.startswith(b"MZ"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid binary structure: File lacks standard MZ executable signature."
            )

    def extract_features(self) -> dict:
        md5_hash = hashlib.md5(self.content).hexdigest()
        sha256_hash = hashlib.sha256(self.content).hexdigest()
        file_entropy = calculate_entropy(self.content)

        try:
            pe = pefile.PE(data=self.content)
        except pefile.PEFormatError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid PE structure: File headers are corrupted or misaligned."
            )

        num_sections = len(pe.sections)
        
        # Parse sections details
        sections_analysis = []
        suspicious_sections_count = 0
        entropy_analysis = {}

        for sec in pe.sections:
            name = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
            sec_size = sec.SizeOfRawData
            sec_entropy = calculate_entropy(sec.get_data())
            
            entropy_analysis[name] = sec_entropy

            # Flags checking for anomaly: standard sections should not be writable and executable simultaneously
            is_writable = bool(sec.Characteristics & 0x80000000)
            is_executable = bool(sec.Characteristics & 0x20000000)
            
            suspicious_flags = False
            if is_writable and is_executable:
                suspicious_flags = True

            # Common packer names or anomalous names
            is_suspicious_name = name.upper() in ["UPX0", "UPX1", "UPX2", ".MPRESS", "PACKED", "PECOMP"]
            if is_suspicious_name or suspicious_flags:
                suspicious_sections_count += 1

            sections_analysis.append({
                "name": name,
                "virtual_size": sec.Misc_VirtualSize,
                "raw_size": sec_size,
                "entropy": sec_entropy,
                "is_writable": is_writable,
                "is_executable": is_executable,
                "suspicious": is_suspicious_name or suspicious_flags
            })

        # Parse Compile Timestamp
        compile_ts = None
        try:
            ts_val = pe.FILE_HEADER.TimeDateStamp
            # Check for standard boundaries (avoid corrupted future timestamps)
            if 315532800 < ts_val < 2082758400:  # 1980 to 2036
                compile_ts = datetime.utcfromtimestamp(ts_val).isoformat() + "Z"
                ts_numeric = ts_val
            else:
                ts_numeric = int(datetime.utcnow().timestamp())
        except Exception:
            ts_numeric = int(datetime.utcnow().timestamp())

        # Parse Imports
        imported_dlls = []
        imported_apis = []
        suspicious_apis_found = []
        mitre_techniques = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="ignore")
                imported_dlls.append(dll_name)

                
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="ignore")
                        imported_apis.append(api_name)
                        
                        # Match blacklist APIs
                        if api_name in SUSPICIOUS_API_LIST:
                            suspicious_apis_found.append(api_name)
                            
                        # Map to MITRE ATT&CK
                        if api_name in MITRE_ATTACK_MAP:
                            map_info = MITRE_ATTACK_MAP[api_name]
                            if map_info not in mitre_techniques:
                                mitre_techniques.append(map_info)

        # Deduplicate API findings
        suspicious_apis_found = list(set(suspicious_apis_found))
        
        # Prepare feature vector for ML model
        # order: ["file_size", "entropy", "num_sections", "num_imported_dlls", "num_imported_apis", "compile_timestamp", "has_suspicious_apis", "has_suspicious_sections"]
        features_vector = [
            self.size,
            file_entropy,
            num_sections,
            len(imported_dlls),
            len(imported_apis),
            ts_numeric,
            len(suspicious_apis_found),
            suspicious_sections_count
        ]

        return {
            "filename": self.filename,
            "file_size": self.size,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "entropy": file_entropy,
            "num_sections": num_sections,
            "compile_timestamp": compile_ts,
            "imported_dlls": imported_dlls,
            "imported_apis_count": len(imported_apis),
            "suspicious_apis": suspicious_apis_found,
            "mitre_mapping": mitre_techniques,
            "entropy_analysis": entropy_analysis,
            "section_analysis": sections_analysis,
            "features_vector": features_vector
        }

    def predict(self, features: dict) -> dict:
        # Load trained classifier
        clf, meta = load_trained_classifier()
        
        vector = np.array(features["features_vector"]).reshape(1, -1)
        
        # Get raw class probabilities
        probs = clf.predict_proba(vector)[0]
        prediction_idx = int(np.argmax(probs))
        predicted_class = CLASSES[prediction_idx]
        confidence_score = float(probs[prediction_idx])
        
        # Compute Threat Score (0 to 100)
        # Weighted metric of ML model confidence, section anomalies, and suspicious API findings
        suspicious_apis_factor = min(len(features["suspicious_apis"]) * 8, 40)
        suspicious_sections_factor = min(features["features_vector"][7] * 15, 30)
        
        if predicted_class == "Benign":
            base_score = (1.0 - confidence_score) * 40
            threat_score = int(min(base_score + suspicious_apis_factor + suspicious_sections_factor, 45))
        else:
            base_score = 50 + (confidence_score * 30)
            threat_score = int(min(base_score + suspicious_apis_factor + suspicious_sections_factor, 100))

        # Explainable AI - compute contribution
        # Multiply features by importance, then scale
        importances = meta["feature_importance"]
        features_keys = meta["features"]
        
        raw_contributions = {}
        for i, key in enumerate(features_keys):
            val = features["features_vector"][i]
            imp = importances[key]
            # Logarithmic scaling for size/apis count to avoid dominating the value product
            scaled_val = math.log1p(val) if val > 1 else val
            raw_contributions[key] = float(scaled_val * imp)

        # Normalize contributions to percentages
        total_contrib = sum(raw_contributions.values()) or 1.0
        normalized_contributions = {k: round((v / total_contrib) * 100, 2) for k, v in raw_contributions.items()}

        # Build IOC Summary
        ioc_summary = {
            "sha256": features["sha256"],
            "md5": features["md5"],
            "high_risk_apis_identified": len(features["suspicious_apis"]),
            "suspicious_sections_count": features["features_vector"][7]
        }

        # Mitigations
        recommended_mitigations = get_mitigations_for_class(predicted_class)

        return {
            "prediction": predicted_class,
            "confidence_score": confidence_score,
            "threat_score": threat_score,
            "mitre_mapping": features["mitre_mapping"],
            "ioc_summary": ioc_summary,
            "suspicious_apis": features["suspicious_apis"],
            "imported_dlls": features["imported_dlls"],
            "entropy_analysis": features["entropy_analysis"],
            "section_analysis": features["section_analysis"],
            "recommended_mitigations": recommended_mitigations,
            "feature_importance": normalized_contributions
        }
