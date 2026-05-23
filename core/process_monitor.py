# process_monitor.py - Process discovery and resource metadata queries using psutil

import psutil
import time

class ProcessMonitor:
    """Discovers, caches, and queries local process tree structures and resource metrics."""
    def __init__(self):
        self._cached_procs = {}

    def get_process_list(self):
        """Scans the operating system process table and returns a mapped list of details."""
        processes = {}
        for proc in psutil.process_iter():
            try:
                # Cache process objects to minimize overhead and fetch CPU status safely
                pid = proc.pid
                
                # Fetch baseline process information
                try:
                    name = proc.name()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    name = "Unknown"
                
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    exe_path = "Access Denied / System Process"
                    
                try:
                    username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = "N/A"
                    
                try:
                    cpu_percent = proc.cpu_percent(interval=0.0) # Non-blocking read
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    cpu_percent = 0.0
                    
                try:
                    mem_info = proc.memory_info()
                    mem_rss = mem_info.rss
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    mem_rss = 0
                    
                try:
                    ppid = proc.ppid()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    ppid = None

                processes[pid] = {
                    "pid": pid,
                    "name": name,
                    "path": exe_path,
                    "user": username,
                    "cpu": cpu_percent,
                    "memory": mem_rss,
                    "ppid": ppid
                }
            except Exception:
                continue
        
        self._cached_procs = processes
        return processes

    def build_process_tree(self, processes_snapshot):
        """Computes a nested parent-child map to model parent-child relationships."""
        children_map = {}
        roots = []
        
        for pid, proc in processes_snapshot.items():
            ppid = proc.get("ppid")
            if ppid and ppid in processes_snapshot:
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(pid)
            else:
                roots.append(pid)
                
        return roots, children_map
