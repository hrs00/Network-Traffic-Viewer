import socket
import struct

TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t  "
DATA_TAB_2 = "\t\t  "
DATA_TAB_3 = "\t\t\t  "
DATA_TAB_4 = "\t\t\t\t  "

d_flag = False

def get_mac_addr(bytes_addr):
    bytes_str = map("{:02x}".format, bytes_addr)
    return ":".join(bytes_str).upper()

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15)*4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return ".".join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = "".join(r"\x{:02x}".format(byte) for byte in string)
    if size % 2:
        size -= 1
        return "\n".join([prefix + line for line in textwrap.wrap(string, size)])

def all():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame: ")
        print(TAB_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))
    
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB_1 + "IPV4 Packet: ")
            print(TAB_2 + "Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print(TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target))
            
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + "ICMP Packet: ")
                print(TAB_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))
        
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + "TCP Segment: ")
                print(TAB_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(TAB_2 + "Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))
                print(TAB_2 + "Flags: ")
                print(TAB_3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))
        
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + "UDP Segment: ")
                print(TAB_2 + "Source Port: {}, Destination: {}, Length: {}".format(src_port, dest_port, length))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))
            else:
                print(TAB_1 + "Non TCP/UDP/ICMP Packet")
                if d_flag:
                    print("Data: ")
                    print(format_multi_line(DATA_TAB_2, data))
        else:
            print(TAB_1 + "Non IPv4 Packet")
            if d_flag:
                print("Data: ")
                print(format_multi_line(DATA_TAB_1, data))

def ip():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        result = ""
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        result += "\nEthernet Frame: \n"
        result += TAB_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto)

        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(result)
            print(TAB_1 + "IPV4 Packet: ")
            print(TAB_2 + "Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
            print(TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + "ICMP Packet: ")
                print(TAB_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))
        
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + "TCP Segment: ")
                print(TAB_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(TAB_2 + "Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))
                print(TAB_2 + "Flags: ")
                print(TAB_3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))
                
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + "UDP Segment: ")
                print(TAB_2 + "Source Port: {}, Destination: {}, Length: {}".format(src_port, dest_port, length))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))
            else:
                print(TAB_1+"Non TCP/UDP/ICMP Packet")
                if d_flag:
                    print("Data: ")
                    print(format_multi_line(DATA_TAB_2, data))

def tcp():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        result = ""
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        result += "\nEthernet Frame: \n"
        result += TAB_1 + "Destination: {}, Source: {}, Protocol: {}\n".format(dest_mac, src_mac, eth_proto)
        
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            result += TAB_1 + "IPV4 Packet: \n"
            result += TAB_2 + "Version: {}, Header Length: {}, TTL: {}\n".format(version, header_length, ttl)
            result += TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target)
            
            if proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(result)
                print(TAB_1 + "TCP Segment: ")
                print(TAB_2 + "Source Port: {}, Destination Port: {}".format(src_port, dest_port))
                print(TAB_2 + "Sequence: {}, Acknowledgement: {}".format(sequence, acknowledgement))
                print(TAB_2 + "Flags: ")
                print(TAB_3 + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))

def udp():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        result = ""
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        result += "\nEthernet Frame: \n"
        result += TAB_1 + "Destination: {}, Source: {}, Protocol: {}\n".format(dest_mac, src_mac, eth_proto)
        
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            result += TAB_1 + "IPV4 Packet: \n"
            result += TAB_2 + "Version: {}, Header Length: {}, TTL: {}\n".format(version, header_length, ttl)
            result += TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target)
            
            if proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(result)
                print(TAB_1 + "UDP Segment: ")
                print(TAB_2 + "Source Port: {}, Destination: {}, Length: {}".format(src_port, dest_port, length))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))

def icmp():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        result = ""
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        result += "\nEthernet Frame: \n"
        result += TAB_1 + "Destination: {}, Source: {}, Protocol: {}\n".format(dest_mac, src_mac, eth_proto)
        
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            result += TAB_1 + "IPV4 Packet: \n"
            result += TAB_2 + "Version: {}, Header Length: {}, TTL: {}\n".format(version, header_length, ttl)
            result += TAB_2 + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target)
            
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(result)
                print(TAB_1 + "ICMP Packet: ")
                print(TAB_2 + "Type: {}, Code: {}, Checksum: {}".format(icmp_type, code, checksum))
                if d_flag:
                    print(TAB_2 + "Data: ")
                    print(format_multi_line(DATA_TAB_3, data))

def non_ip():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        result = ""
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        result += "\nEthernet Frame: \n"
        result += TAB_1 + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto)
        
        if eth_proto == 8:
            pass
        else:
            print(result)
            if d_flag:
                print("Data: ")
                print(format_multi_line(DATA_TAB_1, data))


def handler(response):
    global d_flag
    try:
        if response == "ip":
            ip()
        elif response == "tcp":
            tcp()
        elif response == "udp":
            udp()
        elif response == "icmp":
            icmp()
        elif response == "non-ip":
            non_ip()
        elif response == "all":
            all()
        elif response == "data-on":
            d_flag = True
        elif response == "data-off":
            d_flag = False
        else:
            print("Invalid response in handler")
    except KeyboardInterrupt:
        print("\n")
        return

while True:
    print("Commands:\n\tip: Show IPv4 protocol packets only(includes TCP, UDP, ICMP protocols).\n\ttcp: Show TCP segments only.\n\tudp: Show UDP segments only.\n\ticmp: Show ICMP packets only.\n\tnon-ip: Show only non IPv4 ethernet frames.\n\tall: Show all IPv4 and non IPv4 frames\n\texit: Exit from the command shell\n\tCtrl+C: To quit while packet capturing\n\tdata-on: Show Application data\n\tdata-off: Do not show Application data.")
    if d_flag:
        print("\n\n\t*data-on: Application data will be printed.\n")
    else:
        print("\n\n\t*data-off: Application data will not be printed.\n")
    response = input("ntv-$: ")
    if response in ["ip", "tcp", "udp", "icmp", "non-ip", "all", "data-on", "data-off"]:
        handler(response)
        continue
    elif response == "exit":
        break
    else:
        print("Invalid Command")

