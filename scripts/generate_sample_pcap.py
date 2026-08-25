import struct
import time

def create_sample_pcap(filename):
    # PCAP Global Header (24 bytes)
    # Magic: 0xa1b2c3d4, Version: 2.4, TZ: 0, Sigfigs: 0, Snaplen: 65535, Network: Ethernet (1)
    global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    packets = []
    
    # Packet 1: Minimal Ethernet + IPv4 + TCP SYN (64 bytes)
    eth_header = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00' # Eth (Dst, Src, Type=IPv4)
    # IPv4 (src=192.168.1.50, dst=10.0.0.1, proto=TCP)
    ip_header = b'\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06\x3c\xce\xc0\xa8\x01\x32\x0a\x00\x00\x01'
    # TCP (src_port=49152, dst_port=80, SYN flag)
    tcp_header = b'\xc0\x00\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x50\x02\x20\x00\x91\x7c\x00\x00'
    pkt1_data = eth_header + ip_header + tcp_header
    
    now = int(time.time())
    # Packet Header 1 (16 bytes): ts_sec, ts_usec, incl_len, orig_len
    pkt1_header = struct.pack('<IIII', now, 0, len(pkt1_data), len(pkt1_data))
    packets.append(pkt1_header + pkt1_data)
    
    # Packet 2: Minimal Ethernet + IPv4 + UDP DNS query (64 bytes)
    ip_header2 = b'\x45\x00\x00\x28\x00\x02\x00\x00\x40\x11\x3c\xc4\xc0\xa8\x01\x32\x0a\x00\x00\x01'
    # UDP (src_port=53535, dst_port=53)
    udp_header = b'\xd1\x1f\x00\x35\x00\x14\x00\x00\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    pkt2_data = eth_header + ip_header2 + udp_header
    pkt2_header = struct.pack('<IIII', now + 1, 500000, len(pkt2_data), len(pkt2_data))
    packets.append(pkt2_header + pkt2_data)

    with open(filename, 'wb') as f:
        f.write(global_header)
        for pkt in packets:
            f.write(pkt)

if __name__ == '__main__':
    create_sample_pcap('fixtures/sample_replay.pcap')
    print('Sample PCAP created successfully.')
