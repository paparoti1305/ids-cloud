import subprocess

def block_ip(ip):
    if ip and not ip.startswith(('10.', '192.168.', '172.')):
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd)

def unblock_ip(ip):
    if ip and not ip.startswith(('10.', '192.168.', '172.')):
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd)
