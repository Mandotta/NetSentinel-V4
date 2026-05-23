# ai_engine.py - Threat explanation and risk scoring module (Google Gemini API / Local Fallback)
# Uses the modern google.genai SDK (successor to google.generativeai)

import json
from google import genai
from google.genai import types

class AISecurityExplainer:
    """Provides semantic threat intelligence and risk analysis for detected process actions."""

    # Default model — use gemini-2.0-flash (fast, supports JSON mode)
    GEMINI_MODEL = "gemini-2.0-flash"

    def __init__(self):
        # API key is managed at runtime via the GUI's "API Key" dialog
        self.api_key = ""

    def set_api_key(self, key: str):
        """Called by the GUI API key dialog to update the key at runtime."""
        self.api_key = key.strip()

    def analyze_threat(self, process_info: dict, connections: list, alerts: list) -> dict:
        """
        Computes a threat summary and risk score (0-100).
        Utilizes Google Gemini if an API key is configured, otherwise falls back
        to the local heuristics-based rule engine.
        """
        if self.api_key:
            success, result = self._query_gemini(process_info, connections, alerts)
            if success:
                return result
            fallback_reason = f"Gemini API call failed: {result}. Falling back to local rule engine."
        else:
            fallback_reason = "No Gemini API key configured. Using local heuristics engine."

        risk_score, explanation, recommendation = self._local_heuristics(process_info, connections, alerts)
        return {
            "risk_score": risk_score,
            "explanation": f"[LOCAL ENGINE] {fallback_reason}\n\n{explanation}",
            "recommendation": recommendation
        }

    # ─────────────────── GEMINI API CALL ───────────────────

    def _query_gemini(self, process_info: dict, connections: list, alerts: list):
        """Sends a structured threat prompt to Google Gemini.
        Only called for UNKNOWN and SUSPICIOUS connections.
        Instructs the model to reason from evidence, never assume.
        """
        # Filter to only the relevant connections for AI analysis
        flagged_conns = [
            c for c in connections
            if c.get("classification") in ("UNKNOWN", "SUSPICIOUS")
        ]
        flagged_alerts = [
            a for a in alerts
            if a.get("classification") in ("UNKNOWN", "SUSPICIOUS")
        ]

        prompt = (
            "You are a Windows network security analyst.\n"
            "You are given ONLY unknown or suspicious network activity to evaluate.\n"
            "Do NOT assume the process is malicious or safe — reason only from the evidence provided.\n\n"
            f"Process Name: {process_info.get('name', 'Unknown')}\n"
            f"PID: {process_info.get('pid', 'N/A')}\n"
            f"Executable Path: {process_info.get('path', 'Unknown')}\n"
            f"Running as User: {process_info.get('user', 'Unknown')}\n"
            f"Unknown/Suspicious connection count: {len(flagged_conns)} of {len(connections)} total\n"
            f"Flagged connections:\n{json.dumps(flagged_conns, indent=2)}\n"
            f"Active alerts:\n{json.dumps(flagged_alerts, indent=2)}\n\n"
            "Determine whether this unknown network behaviour is likely:\n"
            "  (a) Normal software activity that should be baselined, or\n"
            "  (b) Potentially malicious and requiring investigation.\n\n"
            "Return a valid JSON object with these exact fields:\n"
            "{\n"
            "  \"risk_score\": <integer 0-100>,\n"
            "  \"explanation\": \"<plain English reasoning from the evidence above>\",\n"
            "  \"recommendation\": \"<specific action for the system administrator>\"\n"
            "}"
        )

        try:
            client = genai.Client(api_key=self.api_key)
            response = client.models.generate_content(
                model=self.GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    temperature=0.2,
                    max_output_tokens=600,
                )
            )

            parsed = json.loads(response.text)

            risk_score = max(0, min(100, int(parsed.get("risk_score", 0))))
            explanation = parsed.get("explanation", "No explanation returned.")
            recommendation = parsed.get("recommendation", "No recommendation returned.")

            return True, {
                "risk_score": risk_score,
                "explanation": explanation,
                "recommendation": recommendation
            }
        except Exception as e:
            return False, str(e)

    # ─────────────────── LOCAL FALLBACK ENGINE ───────────────────

    def _local_heuristics(self, process_info: dict, connections: list, alerts: list):
        """Calculates a risk score using static heuristic rules when Gemini is unavailable."""
        risk_score = 0
        explanations = []
        recommendations = []

        path = process_info.get("path", "").lower()

        # ── Alert severity scoring ──
        critical_alerts = [a for a in alerts if a.get("severity") == "CRITICAL"]
        warning_alerts  = [a for a in alerts if a.get("severity") == "WARNING"]

        if critical_alerts:
            risk_score += len(critical_alerts) * 35
            msgs = "; ".join(a["message"] for a in critical_alerts)
            explanations.append(f"Critical violations: {msgs}")

        if warning_alerts:
            risk_score += len(warning_alerts) * 15
            msgs = "; ".join(a["message"] for a in warning_alerts)
            explanations.append(f"Suspicious behaviors: {msgs}")

        # ── Suspicious execution path ──
        suspicious_paths = (r"\temp", r"\tmp", r"\downloads", r"\desktop", r"\appdata\local\temp")
        if any(sp in path for sp in suspicious_paths):
            risk_score += 25
            explanations.append(
                "Process is executing from an untrusted user-writable directory (Temp/Desktop/Downloads). "
                "This is a common indicator of malware droppers and loaders."
            )
            recommendations.append(
                "Investigate how this binary arrived in user space. "
                "Consider quarantining it before it can persist or execute child processes."
            )

        # ── High established connection count ──
        established = [c for c in connections if c.get("state") == "ESTABLISHED"]
        if len(established) > 20:
            risk_score += 15
            explanations.append(
                f"Unusually high number of established outbound connections ({len(established)}). "
                "This may indicate scanning, data scraping, or data exfiltration activity."
            )
            recommendations.append(
                "Use whois/reverse-DNS to verify all remote IPs belong to expected service endpoints."
            )

        # ── Clean process ──
        if risk_score == 0:
            risk_score = 5
            explanations.append(
                "No suspicious heuristics triggered. "
                "This process matches trusted system operational profiles."
            )
            recommendations.append("No immediate action required. Continue passive monitoring.")
        else:
            risk_score = min(100, risk_score)
            if not recommendations:
                recommendations.append(
                    "Review the process execution chain and monitor any child processes it spawns."
                )

        return risk_score, "\n".join(explanations), "\n".join(sorted(set(recommendations)))
