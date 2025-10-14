from scapy.all import *
 
# ===============================

# Folder path for saving .pcap files

# ===============================

folder = r"C:\Users\Detro\custom-protocol-simulation\WireShark_Lab\\"
 
# ===============================

# 1. Normal Traffic (all successful exchanges)

# ===============================

normal_packets = []
 
# TCP 3-way handshake + HTTP GET + HTTP 200

syn = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=1024, dport=80, flags="S", seq=100)

synack = IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=80, dport=1024, flags="SA", seq=200, ack=101)

ack = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=1024, dport=80, flags="A", seq=101, ack=201)

http_req = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=1024, dport=80, flags="PA", seq=101, ack=201)/Raw(load="GET /index.html HTTP/1.1\r\nHost: 192.168.1.20\r\n\r\n")

http_res = IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=80, dport=1024, flags="PA", seq=201, ack=len(http_req[Raw].load)+101)/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello</html>")

normal_packets += [syn, synack, ack, http_req, http_res]
 
# DNS request/response

dns_q = IP(src="192.168.1.30", dst="192.168.1.40")/UDP(sport=12345, dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))

dns_a = IP(src="192.168.1.40", dst="192.168.1.30")/UDP(sport=53, dport=12345)/DNS(id=dns_q[DNS].id, qr=1, aa=1, qd=dns_q[DNS].qd, an=DNSRR(rrname="example.com", rdata="93.184.216.34"))

normal_packets += [dns_q, dns_a]
 
# ICMP Echo Request + Reply

icmp_req = IP(src="192.168.1.50", dst="192.168.1.60")/ICMP(type="echo-request")

icmp_rep = IP(src="192.168.1.60", dst="192.168.1.50")/ICMP(type="echo-reply")

normal_packets += [icmp_req, icmp_rep]
 
wrpcap(folder + "normal_traffic.pcap", normal_packets)

print("normal_traffic.pcap created!")
 
# ===============================

# 2. Error Traffic (incomplete or broken exchanges)

# ===============================

error_packets = []
 
# TCP SYN without SYN/ACK (handshake never completes)

tcp_half = IP(src="192.168.2.10", dst="192.168.2.20")/TCP(sport=2000, dport=80, flags="S", seq=1000)

error_packets.append(tcp_half)
 
# DNS query without a response (timeout simulation)

dns_bad = IP(src="192.168.2.30", dst="192.168.2.40")/UDP(sport=2222, dport=53)/DNS(rd=1, qd=DNSQR(qname="broken.com"))

error_packets.append(dns_bad)
 
# ICMP Echo Request without reply

icmp_bad = IP(src="192.168.2.50", dst="192.168.2.60")/ICMP(type="echo-request")

error_packets.append(icmp_bad)
 
# Malformed UDP packet (truncated Raw payload)

udp_malformed = IP(src="192.168.2.70", dst="192.168.2.80")/UDP(sport=4000, dport=5000)/Raw(load=b"\x00\x01")

error_packets.append(udp_malformed)
 
wrpcap(folder + "error_traffic.pcap", error_packets)

print("error_traffic.pcap created!")
 
# ===============================

# 3. Request/Response Scenario (HTTP exchange)

# ===============================

req_res_packets = []
 
# Full HTTP request/response

syn = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5000, dport=80, flags="S", seq=50)

synack = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=80, dport=5000, flags="SA", seq=100, ack=51)

ack = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5000, dport=80, flags="A", seq=51, ack=101)

http_req = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5000, dport=80, flags="PA", seq=51, ack=101)/Raw(load="GET /index.html HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n")

http_res = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=80, dport=5000, flags="PA", seq=101, ack=len(http_req[Raw].load)+51)/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Success</html>")

req_res_packets += [syn, synack, ack, http_req, http_res]
 
wrpcap(folder + "request_response.pcap", req_res_packets)

print("request_response.pcap created!")
 
"these packet were generated with the help of generative AI"

 