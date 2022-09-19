# AVISO
# ESSE CODIGO SO PODE SER EXECUTADO EM SISTEMAS LINUX, POR CONTA DA LIB SOCKET
# SOCKET.AF_PACKET NAO PODE SER LIDO PELO WINDOWS 
# EXECUTAR EM LINUX!!!

import socket
import struct
import textwrap
import sys
import pyfiglet

try:
  sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
except socket.error:
  print('[ERROR] Socket nao iniciado.')
  sys.exit(1)

#Capturando o endereco MAC
def get_mac_address(bytesString):
  bytesString = map('{:02x}'.format, bytesString)
  destination_mac = ':'.join(bytesString).upper()
  return destination_mac

#Formatando os Bytes
def format_lines(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

#desempacotando pacotes ICMP
def icmppack(data):
    icmp, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp, code, checksum, data[:4]

#desempacotando seguimentos TCP
def tcp_seg(data):
    (scr_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4 
    flag_urg = (offset_reserved_flags & 32) >> 5   
    flag_ack = (offset_reserved_flags & 16) >> 4 
    flag_psh = (offset_reserved_flags & 8)  >> 3
    flag_rst = (offset_reserved_flags & 4)  >> 2 
    flag_syn = (offset_reserved_flags & 2)  >> 1  
    flag_fin = offset_reserved_flags & 1 
    return scr_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#desempacotando seguimentos UDP
def udp_seg(data):
    scr_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return  scr_port, dest_port, size, data[:8]


ascii_banner = pyfiglet.figlet_format("SNIFFER PACKET") # print banner
print(ascii_banner)
# iniciando captura dos pacotes
while True:

    raw_data, address = sock.recvfrom(65565)
    destination_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw_data[:14])

    destination_mac = get_mac_address(destination_mac)
    src_mac = get_mac_address(src_mac)
    ethernet_proto = socket.htons(ethernet_proto)
    data = raw_data[14:]

    print('\nEthernet frame:')
    print('\tDestination: {}, Source: {}, Ethernet Protocol: {}'.format(destination_mac, src_mac, ethernet_proto))

    if ethernet_proto == 8:
        version_header_len = data[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        ttl,proto,src,target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

        src = '.'.join(map(str,src)) 
        target = '.'.join(map(str,target)) 
    
        print('IPv4 packet:')
        print('\tVersion: {}, Header length: {}, TTL: {}'.format(version,header_len,ttl))
        print('\tProtocol: {}, Source: {}, Target: {}'.format(proto,src,target))
 
        if proto == 1:
            icmp, code, checksum, data = icmppack(data)
            print('Pacotes ICMP\t')
            print('Type: {} Code: {} Checksum: {}\t'.format(icmp, code, checksum))
            print('Data: ')
            #print(format_lines(data))

        elif proto == 6:
            scr_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_seg(data)
            print('Pacotes TCP\t')
            print('Source Port: {} Destination Port: {}'.format(scr_port, dest_port))
            print('Sequence: {} Acknowledgement: {}'.format(sequence, acknowledgement))
            print('Flags\t')
            print('URG: {} ACK: {} PSH: {} RST: {} SYN: {} FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
            print('Data\t')
            #print(format_lines(data))

        elif proto == 17:
            scr_port, dest_port, lenght, data = udp_seg(data)
            print('Pacotes UDP\t')
            print('Source Port: {} Destination Port {} Lenght {}'.format(scr_port, dest_port, lenght))

        else:
            print('Data\n')
            print(format_lines(data))

    else:
        print('Data\n')
        print(format_lines(data))       