import socket
import struct
import textwrap

def main():
    """Main function to capture and display network packets."""
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #raw socket
    except socket.error as msg:
        print('Socket creation failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        return

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:  # IPv4
            (version, header_length, ttl, proto, src, target, data) = ipv4_packets(data)
            print('IPv4 Packet:')
            print('Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 6:  # TCP
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segments(data)
                print('TCP Segment:')
                print('Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print('Flags: URG={}, ACK={}, PSH={}, RST={}, SYN={}, FIN={}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('Data:\n' + format_multi_line(DATA_TAB_3, data))

            elif proto == 17:  # UDP
                src_port, dest_port, length, data = udp_segments(data)
                print('UDP Segment:')
                print('Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
                print('Data:\n' + format_multi_line(DATA_TAB_3, data))

            elif proto == 1: #ICMP
                icmp_type, code, checksum, data = icmp_packets(data)
                print('ICMP Packet:')
                print('Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print('Data:\n' + format_multi_line(DATA_TAB_3, data))

        elif eth_proto == 1544: #ARP
            print("ARP Packet")
            #add ARP parsing here if desired.
        else:
            print('Data:\n' + format_multi_line(DATA_TAB_1, data))

# Unpack Ethernet Frame
def ethernet_frame(data):
    """Parses ethernet frame data."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return properly formatted MAC address (ie AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    """Formats MAC address."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 Packets
def ipv4_packets(data):
    """Parses IPv4 packet data."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ip(src), get_ip(target), data[header_length:]

# Returns properly formatted IPv4 address
def get_ip(addr):
    """Formats IPv4 address."""
    return '.'.join(map(str, addr))

# Unpack TCP Segments
def tcp_segments(data):
    """Parses TCP segment data."""
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP Segments
def udp_segments(data):
    """Parses UDP segment data."""
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, length, data[8:]

# ICMP Packets unpack
def icmp_packets(data):
    """Parses ICMP packet data."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Format multi-line data
def format_multi_line(prefix, string, size=80):
    """Formats multi-line data for output."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

if __name__ == "__main__":
    main()