import os
import requests

class VirusTotalService:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.headers = {
            "x-apikey": self.api_key
        } if self.api_key else {}

    def check_hash(self, file_hash: str):
        """
        Queries VirusTotal v3 API for file hash report.
        Returns dictionary of scan results or None if disabled/unconfigured.
        """
        if not self.api_key:
            return None
        
        # VirusTotal V3 API URL for files
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers, timeout=6)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                last_analysis_stats = attributes.get("last_analysis_stats", {})
                return {
                    "harmless": last_analysis_stats.get("harmless", 0),
                    "suspicious": last_analysis_stats.get("suspicious", 0),
                    "malicious": last_analysis_stats.get("malicious", 0),
                    "undetected": last_analysis_stats.get("undetected", 0),
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                    "status": "found"
                }
            elif response.status_code == 404:
                return {
                    "status": "not_found",
                    "message": "File hash not catalogued in VirusTotal database."
                }
            else:
                return {
                    "status": "error",
                    "message": f"VirusTotal API returned HTTP {response.status_code}"
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Could not connect to VirusTotal: {str(e)}"
            }
