import socket
import struct

# Function to process IP header
def process_ip_header(data):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, ihl, ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(target)

# Function to process TCP segment
def process_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Create a raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# Bind the socket to the interface
s.bind(("YOUR_INTERFACE_IP_ADDRESS", 0))

# Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Enable promiscuous mode
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        raw_data, addr = s.recvfrom(65535)
        version, ihl, ttl, proto, src, target = process_ip_header(raw_data)
        print(f'IP Version: {version}, Header Length: {ihl}, TTL: {ttl}')
        print(f'Protocol: {proto}, Source: {src}, Target: {target}')
        
        # If the protocol is TCP, process the TCP segment
        if proto == 6:
            src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = process_tcp_segment(raw_data[ihl:])
            print(f'Source Port: {src_port}, Destination Port: {dest_port}')
            print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
            print('Flags:')
            print(f'URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
            if data:
                print(f'Data: {data}')
except KeyboardInterrupt:
    print('Stopping packet sniffer...')
    # Disable promiscuous mode
    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)