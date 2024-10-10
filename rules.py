class rulesManager:
    def __init__(self):
        self.rules = []

    def addRule(self, src_ip, dst_ip, protocol, src_port=None, dst_port=None, action='allow'):
        rule = {
            'src_ip': src_ip,
            'dst_ip':dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'action':action
        }

        self.rules.append(rule)

    def checkRule(self, src_ip, dst_ip, protocol, packet):
        for rule in self.rules:
            if not self.match_ip(rule['src_ip'], src_ip):
                continue
            if not self.match_ip(rule['dst_ip'], dst_ip):
                continue
            if rule['protocol'] != protocol and rule['protocol'] != '*':
                continue
            if rule['src_port'] and not self.match_port(rule['src_port'], packet[20:22]):
                continue
            if rule['dst_port'] and not self.match_port(rule['dst_port'], packet[22:24]):
                continue

            return rule['action'] == 'allow'
        return False
    
    def match_ip(self, rule_ip, packet_ip):
        return rule_ip == packet_ip or rule_ip == '*'
    
    def match_port(self, rule_port, packet_port):
        return int.from_bytes(packet_port, 'big') == rule_port
