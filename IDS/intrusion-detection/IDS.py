import sys
from scapy.all import rdpcap, IP, TCP, ICMP, UDP, Raw
from datetime import datetime
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from collections import deque

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

#parse .pcap file
def parse_pcap(file_path):
    
    packets = rdpcap(file_path)
    
    return packets

#parsing IDS rules
def parse_rules(file_path):
    rules = []
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('#') or not line:
                continue
            action, rule = line.split('(', 1)
            rule_content = rule.strip(')').split(';')
            rules.append((action.strip(), rule_content))
    
    return rules

#use current system timestamp
def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

#alert logs
def log_alert(log_file, protocol, src_ip=None, dst_ip=None, rule_msg=None, flooding=False):
    timestamp = get_timestamp()

    if flooding:  #handle TCP flooding
        log_message = f"{timestamp} - Alert: TCP flooding detected"
    elif rule_msg:  #the custom message
        log_message = f"{timestamp} - Alert: {rule_msg}"
    else:
        #if ip is not none, log it
        if src_ip and dst_ip:
            log_message = f"{timestamp} - Alert: receive a {protocol} packet from {src_ip} to {dst_ip}"
        else:
            log_message = f"{timestamp} - Alert: receive a {protocol} packet"
    
    log_file.write(log_message + "\n")
    print(log_message)

#to check tcp flags
def match_flag_tcp(packet_flags, rule_flags):
    flag_mapping = {
        'S': 0x02,  # SYN
        'A': 0x10,  # ACK
        'F': 0x01,  # FIN
        'R': 0x04   # RST
    }
    
    for flag in rule_flags:
        if flag not in flag_mapping:
            return False
        
        required_flag_value = flag_mapping[flag]
        if (packet_flags & required_flag_value) == 0:  #flag is not set
            return False
        
    return True

#detect TCP SYN scan
def detect_syn_scan(packets, src_ip, dst_ip, src_port, dst_port, threshold_count, threshold_seconds, log_file, custom_msg):
    time_window_start = None
    count = 0
    syn_packets = []

    for packet in packets:
        if packet.haslayer(TCP):
            packet_src_ip = packet[IP].src
            packet_dst_ip = packet[IP].dst
            packet_src_port = packet[TCP].sport
            packet_dst_port = packet[TCP].dport
            packet_flags = packet[TCP].flags

            #check if packet = SYN and match rule of IP and port
            if (packet_flags & 0x02) and \
               (src_ip == "any" or packet_src_ip == src_ip) and \
               (dst_ip == "any" or packet_dst_ip == dst_ip) and \
               (src_port is None or packet_src_port == src_port) and \
               (dst_port is None or packet_dst_port == dst_port):
                
                if time_window_start is None:
                    time_window_start = packet.time

                if packet.time - time_window_start <= threshold_seconds:
                    count += 1
                else:
                    time_window_start = packet.time
                    count = 1  #count is reset for new window

                if count >= threshold_count:
                    syn_packets.append(packet)

    #log alert SYN scan
    for packet in syn_packets:
        log_alert(log_file, "tcp", src_ip=packet[IP].src, dst_ip=packet[IP].dst, rule_msg=custom_msg)

#detect TCP with flags and malicious content
def detect_malicious_tcp(packets, src_ip, dst_ip, src_port, dst_port, threshold_count, threshold_seconds, log_file, custom_msg, flag_type, content):
    time_window_start = None
    count = 0
    malicious_packets = []

    for packet in packets:
        if packet.haslayer(TCP):
            packet_src_ip = packet[IP].src
            packet_dst_ip = packet[IP].dst
            packet_src_port = packet[TCP].sport
            packet_dst_port = packet[TCP].dport
            packet_flags = packet[TCP].flags

            #check if packet match the specified flags
            flag_matched = match_flag_tcp(packet_flags, flag_type)

            #check if content contains malicious contents
            if packet.haslayer(Raw):
                payload_bytes = bytes(packet[Raw].load)
                content_matched = content.encode().lower() in payload_bytes.lower()
            else:
                content_matched = False

            #both flag and content match, check IP and port, after that, packet is counted
            if flag_matched and content_matched and \
               (src_ip == "any" or packet_src_ip == src_ip) and \
               (dst_ip == "any" or packet_dst_ip == dst_ip) and \
               (src_port is None or packet_src_port == src_port) and \
               (dst_port is None or packet_dst_port == dst_port):

                if time_window_start is None:
                    time_window_start = packet.time

                if packet.time - time_window_start <= threshold_seconds:
                    count += 1
                else:
                    time_window_start = packet.time
                    count = 1  #reset count for new window
                if count >= threshold_count:
                    malicious_packets.append(packet)

    #log alerts for malicious packets
    for packet in malicious_packets:
        log_alert(log_file, "tcp", src_ip=packet[IP].src, dst_ip=packet[IP].dst, rule_msg=custom_msg)

# Source: ChatGPT, OpenAI, "Rules applied to each packet & adjust detection filter function", Sep. 2024. 
# [Online]. Available: https://chat.openai.com/
#rules apllied to each packet & adjust detection filter
def apply_rules(packets, rules):
    with open('IDS_log.txt', 'w') as log_file:
        detection_window = {}

        #iterate through each packet, then apply all rules
        for packet in packets:
            if packet.haslayer(IP):  #if packet has ip layer
                protocol, packet_src_ip, packet_dst_ip = None, packet[IP].src, packet[IP].dst
                src_port = None
                dst_port = None

                if packet.haslayer(TCP):
                    protocol = "tcp"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol = "udp"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol = "icmp"
                else:
                    protocol = "ip"

                packet_time = packet.time  #get packet's time

                #iterate through each rule (current packet)
                for action, rule_content in rules:
                    detection_filter = None
                    custom_msg = None
                    flag_type = None
                    content = None
                    threshold_count = None
                    threshold_seconds = None

                    #check rule content (flags, content, detection filter, message)
                    for field in rule_content:
                        if 'detection_filter:' in field:
                            filter_info = field.split(':')[1].strip().split(',')
                            threshold_count = int(filter_info[0].split()[1])
                            threshold_seconds = int(filter_info[1].split()[1])
                            detection_filter = (threshold_count, threshold_seconds)
                        elif 'msg:' in field:
                            custom_msg = field.split('msg:')[1].strip().strip('"')
                        elif 'flags:' in field:
                            flag_type = field.split('flags:')[1].strip()
                        elif 'content:' in field:
                            content = field.split('content:')[1].strip().strip('"')

                    #check IPs and Ports from rule
                    rule_parts = action.split()
                    rule_protocol = rule_parts[1]
                    rule_src_ip = rule_parts[2]
                    rule_dst_ip = rule_parts[5]
                    rule_src_port = rule_parts[3] if len(rule_parts) > 3 else None
                    rule_dst_port = rule_parts[6] if len(rule_parts) > 6 else None

                    #current packet is matched with current rule
                    if match_packet(packet, action, rule_content):
                        #handle detection filter
                        if detection_filter:
                            rule_key = (rule_src_ip, rule_dst_ip, flag_type)
                            if rule_key not in detection_window:
                                detection_window[rule_key] = []

                            #use current packet time to detection window
                            detection_window[rule_key].append(packet_time)

                            #outside detection window, current packet time is removed
                            detection_window[rule_key] = [t for t in detection_window[rule_key] if packet_time - t <= threshold_seconds]

                            #if the count exceeds the threshold
                            if len(detection_window[rule_key]) > threshold_count:
                                #log alert
                                log_alert(log_file, protocol, src_ip=packet_src_ip, dst_ip=packet_dst_ip, rule_msg=custom_msg)
                        else:
                            #log for no detection filters
                            log_alert(log_file, protocol, src_ip=packet_src_ip, dst_ip=packet_dst_ip, rule_msg=custom_msg)


#match packet content including TCP flags
def match_packet(packet, rule_action, rule_content):
    protocol = None
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = None
    dst_port = None
    tcp_flags = None

    if packet.haslayer(TCP):
        protocol = "tcp"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags  #get TCP flag
    elif packet.haslayer(UDP):
        protocol = "udp"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol = "icmp"
    else:
        protocol = "ip"  #just ip packet, with no layers

    rule_parts = rule_action.split()
    rule_protocol = rule_parts[1]
    rule_src_ip = rule_parts[2]
    rule_dst_ip = rule_parts[5]
    rule_src_port = rule_parts[3] if len(rule_parts) > 3 else None
    rule_dst_port = rule_parts[6] if len(rule_parts) > 6 else None

    #protocol match
    if protocol != rule_protocol and rule_protocol != "ip":
        return False

    #IP match
    ip_match = (rule_src_ip == "any" or src_ip == rule_src_ip) and (rule_dst_ip == "any" or dst_ip == rule_dst_ip)

    #TCP or UDP port match
    port_match = True
    if protocol in ["tcp", "udp"]:
        port_match = (rule_src_port == "any" or src_port == int(rule_src_port)) and \
                     (rule_dst_port == "any" or dst_port == int(rule_dst_port))

    #TCP flag match (rule has flags)
    flag_match = True
    for field in rule_content:
        if 'flags:' in field:
            rule_flags = field.split('flags:')[1].strip()
            flag_match = match_flag_tcp(tcp_flags, rule_flags)

    return ip_match and port_match and flag_match

# Source: ChatGPT, OpenAI, "Flood detection function for TCP packets", Sep. 2024. 
# [Online]. Available: https://chat.openai.com/
#flood detection function for TCP packets
def detect_tcp_flooding(packets, src_ip, dst_ip, src_port, dst_port, threshold_count, threshold_seconds, log_file):
    time_window_start = None
    count = 0
    excess_packets = []

    for packet in packets:
        if packet.haslayer(TCP):
            packet_src_ip = packet[IP].src
            packet_dst_ip = packet[IP].dst
            packet_src_port = packet[TCP].sport
            packet_dst_port = packet[TCP].dport

            #packet matches the rule's IP and port
            if (src_ip == "any" or packet_src_ip == src_ip) and \
               (dst_ip == "any" or packet_dst_ip == dst_ip) and \
               (src_port is None or packet_src_port == src_port) and \
               (dst_port is None or packet_dst_port == dst_port):

                if time_window_start is None:
                    time_window_start = packet.time

                if packet.time - time_window_start <= threshold_seconds:
                    count += 1
                else:
                    time_window_start = packet.time
                    count = 1  #new window reset count

                if count > threshold_count:
                    excess_packets.append(packet)

    #after threshold log alert
    for packet in excess_packets:
        log_alert(log_file, "tcp", src_ip=packet[IP].src, dst_ip=packet[IP].dst, flooding=True)


#Main function
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("python IDS.py <path_to_pcap_file> <path_to_ids_rules>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    rules_file = sys.argv[2]
    
    packets = parse_pcap(pcap_file)
    rules = parse_rules(rules_file)

    apply_rules(packets, rules)
