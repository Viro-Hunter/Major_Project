from typing import Dict

def block_ip(ip: str) -> Dict:
    return {"action": "block_ip", "target": ip, "status": "simulated_success", "message": f"IP {ip} would be blocked (simulated)"}

def force_reauth_user(user_id: str) -> Dict:
    return {"action": "force_reauth", "target": user_id, "status": "simulated_success", "message": f"User {user_id} would be forced to re-authenticate"}

def quarantine_host(host: str) -> Dict:
    return {"action": "quarantine_host", "target": host, "status": "simulated_success", "message": f"Host {host} would be quarantined"}
