import re
from collections import defaultdict

class SimpleSIEM:
    def __init__(self):
        self.failed_logins = defaultdict(int)
        self.threshold = 5
        
    def parse_log(self, line):
        # Extract IP, status code, and endpoint from Apache log
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*"(GET|POST) (/\S*) .*" (\d+)', line)
        if match:
            return {
                'ip': match.group(1),
                'method': match.group(2),
                'endpoint': match.group(3),
                'status': int(match.group(4))
            }
        return None
    
    def analyze(self, log_line):
        event = self.parse_log(log_line)
        if not event:
            return
            
        # Brute-force detection: 5+ failed logins from same IP
        if event['status'] == 401:
            self.failed_logins[event['ip']] += 1
            if self.failed_logins[event['ip']] >= self.threshold:
                print(f"[ALERT] BRUTE_FORCE - {event['ip']} - {self.failed_logins[event['ip']]} failed logins")
