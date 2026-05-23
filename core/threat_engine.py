# threat_engine.py - 4-tier classification + alert engine for NetSentinel v4
#
# Classification order (highest wins unless SUSPICIOUS override):
#   TRUSTED  -> known safe process in safe path
#   NORMAL   -> recognised software with expected behaviour
#   UNKNOWN  -> first-seen process/IP pair, no baseline, cannot classify confidently
#   SUSPICIOUS -> matches malicious-port rule OR unsafe path + unknown network activity

import re
import time
from collections import defaultdict


class ThreatEngine:
    """Security verification engine: heuristic rules, 4-tier connection classification,
    first-seen tracking, and user-maintained safe baseline."""

    # ─────────────────────── STATIC KNOWLEDGE BASES ───────────────────────

    SUSPICIOUS_PORTS = {
        21:    "FTP (often targeted/exploited)",
        23:    "Telnet (unencrypted protocol)",
        139:   "NetBIOS Session (SMB payload risk)",
        445:   "SMB (high-target exploit entrypoint)",
        3389:  "RDP (Remote Desktop administrative control)",
        4444:  "Metasploit payload default listener",
        5900:  "VNC (Remote control service)",
        31337: "Back Orifice backdoor port",
    }

    SUSPICIOUS_PATHS = [
        r"\temp", r"\tmp", r"\appdata\local\temp",
        r"\downloads", r"\desktop", r"\recycle", r"\public",
    ]

    SUSPICIOUS_PROCESS_PATTERNS = [
        r"^[a-z]{1,4}\.exe$",
        r"svchost\d+\.exe",
        r"^(update|patch|install)\.exe$",
        r"^[0-9a-f]{8,}\.exe$",
    ]

    TRUSTED_DIRECTORIES = [
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\windows\\winsxs",
        "c:\\program files",
        "c:\\program files (x86)",
    ]

    # Core OS processes — always TRUSTED regardless of connections
    TRUSTED_PROCESSES = {
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe",
        "csrss.exe", "smss.exe", "explorer.exe", "spoolsv.exe",
        "taskhostw.exe", "winlogon.exe", "dwm.exe", "sihost.exe",
        "smartscreen.exe", "wuauclt.exe", "msiexec.exe", "dllhost.exe",
    }

    # Common software expected to have regular network activity → NORMAL
    NORMAL_PROCESSES = {
        "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
        "onedrive.exe", "dropbox.exe", "googledrivesync.exe",
        "teams.exe", "slack.exe", "zoom.exe", "discord.exe",
        "spotify.exe", "steam.exe", "epicgameslauncher.exe",
        "code.exe", "cursor.exe",
        "python.exe", "pythonw.exe", "node.exe", "java.exe",
        "git.exe", "ssh.exe", "openssh.exe",
        "mongod.exe", "postgres.exe", "mysqld.exe", "redis-server.exe",
        "vmware-authd.exe", "vmms.exe",
        "antigravity.exe", "esrv.exe", "esrv_svc.exe",
        "winstore.app.exe", "microsoftedgewebview2.exe",
    }

    def __init__(self):
        # ── First-seen tracking ──
        self.seen_remote_ips: set = set()
        self.seen_process_ip_pairs: set = set()   # (process_name, remote_ip)

        # ── Last-seen timestamps for every unique pair ──
        self.last_seen: dict = {}   # (proc_name, remote_ip) -> float timestamp

        # ── User-defined safe baseline (persists for session) ──
        self.user_safe_processes: set = set()     # manually trusted process names
        self.user_safe_ips: set = set()           # manually trusted remote IPs

        # ── Volume baseline ──
        self.connection_count_history = defaultdict(list)

    # ─────────────────────── PUBLIC API ───────────────────────

    def mark_safe_process(self, process_name: str):
        """User action: permanently classify a process name as TRUSTED for this session."""
        self.user_safe_processes.add(process_name.lower())

    def mark_safe_ip(self, remote_ip: str):
        """User action: permanently classify a remote IP as safe (NORMAL)."""
        self.user_safe_ips.add(remote_ip)

    def create_baseline(self, processes: dict, connections: list):
        """Snapshot all currently seen IPs and process-IP pairs as baseline (NORMAL)."""
        for conn in connections:
            if conn.get("state") == "ESTABLISHED" and conn.get("remote_ip"):
                self.seen_remote_ips.add(conn["remote_ip"])
                pid = conn.get("pid")
                proc = processes.get(pid)
                if proc:
                    pair = (proc["name"].lower(), conn["remote_ip"])
                    self.seen_process_ip_pairs.add(pair)

    # ─────────────────────── CLASSIFICATION ENGINE ───────────────────────

    def classify_connection(self, conn: dict, proc: dict | None) -> tuple[str, str]:
        """
        Returns (classification, reason) for a single connection.
        Classification: TRUSTED | NORMAL | UNKNOWN | SUSPICIOUS
        Evaluation order: SUSPICIOUS check → TRUSTED → NORMAL → UNKNOWN
        """
        remote_ip   = conn.get("remote_ip")
        remote_port = conn.get("remote_port")
        state       = conn.get("state", "")

        # ── No process info ──
        if not proc:
            if remote_ip:
                return "UNKNOWN", "Connection has no associated process in the process table"
            return "NORMAL", "Listening socket with no process mapping (system)"

        name      = proc.get("name", "").lower()
        path      = proc.get("path", "").lower()
        is_listening = (state == "LISTENING")
        is_private_ip = self._is_private(remote_ip) if remote_ip else True

        # ──────── 1. SUSPICIOUS OVERRIDE ────────
        # Port match on outbound → always SUSPICIOUS regardless of trust level
        if remote_port in self.SUSPICIOUS_PORTS and not is_listening:
            desc = self.SUSPICIOUS_PORTS[remote_port]
            return "SUSPICIOUS", f"Outbound connection to known-malicious port {remote_port} ({desc})"

        # Listening on suspicious port (exposed externally)
        if is_listening:
            local_ip  = conn.get("local_ip", "")
            port      = conn.get("local_port")
            exposed   = local_ip in ("0.0.0.0", "[::]", "::")
            skip_smb  = (name in ("system", "system.exe") and port in (139, 445))
            if not skip_smb and port in self.SUSPICIOUS_PORTS and exposed:
                desc = self.SUSPICIOUS_PORTS[port]
                return "SUSPICIOUS", f"Exposed listener on suspicious port {port} ({desc})"

        # Execution from untrusted directory
        is_sus_path = any(sp in path for sp in self.SUSPICIOUS_PATHS)
        has_ext_network = (state == "ESTABLISHED" and remote_ip and not is_private_ip)
        if is_sus_path and has_ext_network:
            return "SUSPICIOUS", f"Process executing from untrusted directory and has external network activity"

        # User-flagged but has suspicious-port outbound
        # (covered above already — just guard suspicious name patterns for unknowns)
        name_sus = any(re.match(p, name) for p in self.SUSPICIOUS_PROCESS_PATTERNS)

        # ──────── 2. TRUSTED ────────
        in_trusted_dir = any(path.startswith(d) for d in self.TRUSTED_DIRECTORIES)
        is_user_safe   = name in self.user_safe_processes

        if (name in {p.lower() for p in self.TRUSTED_PROCESSES} or is_user_safe or in_trusted_dir) \
                and not name_sus:
            return "TRUSTED", f"Known Windows system process or user-verified safe"

        # ──────── 3. NORMAL ────────
        is_safe_ip = (remote_ip in self.user_safe_ips) if remote_ip else False
        is_normal_proc = name in {p.lower() for p in self.NORMAL_PROCESSES}
        known_pair = (name, remote_ip) in self.seen_process_ip_pairs if remote_ip else False

        if is_normal_proc or is_safe_ip or (is_private_ip and not name_sus) or known_pair:
            return "NORMAL", self._normal_reason(is_normal_proc, is_safe_ip, is_private_ip, known_pair)

        # ──────── 4. UNKNOWN ────────
        # Reaches here if: not trusted, not normal, and didn't trigger SUSPICIOUS rules
        is_new_ip   = (remote_ip not in self.seen_remote_ips) if (remote_ip and not is_private_ip) else False
        is_new_pair = (remote_ip is not None) and ((name, remote_ip) not in self.seen_process_ip_pairs)

        reasons = []
        if is_new_ip:
            reasons.append(f"first time this remote IP has been seen ({remote_ip})")
        if is_new_pair:
            reasons.append(f"first time '{name}' connected to this destination")
        if not reasons:
            reasons.append("process has no established baseline or whitelist match")

        return "UNKNOWN", "; ".join(reasons)

    # ─────────────────────── MAIN ANALYZE ───────────────────────

    def analyze(self, processes: dict, connections: list) -> list:
        """
        Full sweep: classifies every connection and generates alert entries.
        Returns a list of alert dicts (kept for backwards-compatibility with dashboard).
        Also stamps each connection in-place with 'classification' and 'reason'.
        """
        alerts = []
        pid_conns = defaultdict(list)
        for conn in connections:
            pid = conn.get("pid")
            if pid:
                pid_conns[pid].append(conn)

        # Volume baseline
        total_est = 0
        est_by_proc = {}
        for pid, conns in pid_conns.items():
            count = sum(1 for c in conns if c["state"] == "ESTABLISHED")
            est_by_proc[pid] = count
            total_est += count
        avg_est = (total_est / len(pid_conns)) if pid_conns else 0

        now = time.time()

        for conn in connections:
            pid  = conn.get("pid")
            proc = processes.get(pid)

            # ── Classify ──
            classification, reason = self.classify_connection(conn, proc)
            conn["classification"] = classification
            conn["reason"] = reason

            remote_ip = conn.get("remote_ip")
            name = proc["name"].lower() if proc else None

            # ── Update first-seen tracking ──
            if remote_ip and conn.get("state") == "ESTABLISHED":
                self.seen_remote_ips.add(remote_ip)
                if name:
                    pair = (name, remote_ip)
                    self.seen_process_ip_pairs.add(pair)
                    self.last_seen[pair] = now

            # ── Alerts for non-TRUSTED / non-NORMAL ──
            if not proc:
                continue

            name_display = proc["name"]

            if classification == "SUSPICIOUS":
                alerts.append({
                    "severity": "CRITICAL",
                    "process_name": name_display,
                    "pid": pid,
                    "message": f"[SUSPICIOUS] '{name_display}' (PID {pid}): {reason}",
                    "classification": "SUSPICIOUS",
                })
            elif classification == "UNKNOWN":
                alerts.append({
                    "severity": "WARNING",
                    "process_name": name_display,
                    "pid": pid,
                    "message": f"[UNKNOWN] '{name_display}' (PID {pid}): {reason}",
                    "classification": "UNKNOWN",
                })

        # ── Volume spike check (only for UNKNOWN / not trusted) ──
        for pid, conns in pid_conns.items():
            proc = processes.get(pid)
            if not proc:
                continue
            name_display = proc["name"]
            name_lower   = name_display.lower()
            is_trusted   = name_lower in {p.lower() for p in self.TRUSTED_PROCESSES} \
                           or name_lower in {p.lower() for p in self.NORMAL_PROCESSES} \
                           or name_lower in self.user_safe_processes
            est_count = est_by_proc.get(pid, 0)
            if est_count > 0:
                self.connection_count_history[name_lower].append(est_count)
                if len(self.connection_count_history[name_lower]) > 50:
                    self.connection_count_history[name_lower].pop(0)
            if est_count > max(avg_est * 4, 30) and not is_trusted:
                alerts.append({
                    "severity": "WARNING",
                    "process_name": name_display,
                    "pid": pid,
                    "message": f"[ANOMALY] '{name_display}' (PID {pid}) has {est_count} connections"
                               f" vs system avg {avg_est:.1f}",
                    "classification": "SUSPICIOUS",
                })

        return alerts

    # ─────────────────────── HELPERS ───────────────────────

    @staticmethod
    def _is_private(ip: str) -> bool:
        if not ip:
            return True
        if ip in ("127.0.0.1", "::1", "0.0.0.0"):
            return True
        if ip.startswith("192.168.") or ip.startswith("10."):
            return True
        parts = ip.split(".")
        if len(parts) == 4 and parts[1].isdigit() and ip.startswith("172."):
            return 16 <= int(parts[1]) <= 31
        return False

    @staticmethod
    def _normal_reason(is_normal_proc, is_safe_ip, is_private, known_pair) -> str:
        if is_safe_ip:
            return "Remote IP marked as safe by user"
        if is_normal_proc:
            return "Known software with expected network behaviour"
        if is_private:
            return "Local / private network connection (LAN)"
        if known_pair:
            return "Previously seen process-IP pair (baseline match)"
        return "Classified as normal"
