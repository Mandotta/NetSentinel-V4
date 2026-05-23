# network_monitor.py - Socket connection tracker for NetSentinel v4

import psutil

class NetworkMonitor:
    """Retrieves and normalizes system socket entries using native psutil APIs."""
    def __init__(self):
        pass

    def get_connections(self):
        """Scans the system network table and returns active/listening connections."""
        connections = []
        try:
            # We scan for 'inet' family (both IPv4 and IPv6)
            net_conns = psutil.net_connections(kind='inet')
            for conn in net_conns:
                # We prioritize LISTENING and ESTABLISHED connection states
                if conn.status not in ('ESTABLISHED', 'LISTENING'):
                    continue

                local_ip, local_port = conn.laddr
                
                remote_addr = None
                remote_ip = None
                remote_port = None
                if conn.raddr:
                    remote_ip, remote_port = conn.raddr
                    remote_addr = (remote_ip, remote_port)

                connections.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": conn.status,
                    "pid": conn.pid
                })
        except Exception:
            pass
        return connections
