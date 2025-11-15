import socket
import struct

TAB = '\t'
TAB1 = '\t \t'
TAB2 = '\t \t \t'


def main():
    host = socket.gethostbyname(socket.gethostname())
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    conn.bind((host, 0))
    conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    while True:
        raw_data, addr = conn.recvfrom(65536)
        version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
        
        print('IP Packet:')
        print(TAB + f'Version: {version}, Source IP: {src}, Destination IP: {target}, Header Length: {header_length},TTL: {ttl},Protocol: {proto}')

        if proto == 6:
            src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_packet(data)
            print(TAB + 'TCP segment - ')
            print(TAB1 + f'Source port: {src_port}, Destination port: {dest_port}, Sequence: {sequence}, acknowledgment: {acknowledgment}')
            print(TAB1 + f'Flags - ')
            print(TAB2 + f'URG:{flag_urg}, ACK:{flag_ack}, PUS:{flag_psh}, RST:{flag_rst}, SYN:{flag_syn}, FIN:{flag_fin}\n')

        elif proto == 17:
            src_port, dest_port, size, data = udp_segment(data)
            print(TAB + 'UDP segment - ')
            print(TAB1 + f'Source port:{src_port}, Destination port:{dest_port}, Size:{size}\n')


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_packet(data):
    sec_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12)*4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return sec_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


if __name__ == "__main__":
    main()
