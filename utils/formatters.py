# formatters.py - Formatting utility functions for NetSentinel v4

def format_bytes(num_bytes):
    """Formats bytes to human-readable strings (KB, MB, GB)."""
    if num_bytes is None:
        return "N/A"
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.2f} TB"

def format_percentage(val):
    """Formats values as percentage strings."""
    if val is None:
        return "N/A"
    return f"{val:.1f}%"

def format_addr(ip, port):
    """Combines IP and port into a standardized string."""
    if not ip:
        return "N/A"
    # Wrap IPv6 address in brackets
    if ":" in ip and not ip.startswith("["):
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"
