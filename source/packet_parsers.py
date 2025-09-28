# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    elif ether_type == "0800":
        parse_ipv4_header(payload)
    elif ether_type == "86dd":
        parse_ipv6_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


def format_mac(mac_hex):
    return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))

def format_ip(ip_hex):
    ip_parts = []
    for i in range(0, 8, 2):
        hex_byte = ip_hex[i:i+2]
        decimal_octet = str(int(hex_byte, 16))
        ip_parts.append(decimal_octet)
    return ".".join(ip_parts)

def format_ipv6(ipv6_hex):
    return ":".join(ipv6_hex[i:i+4].lower() for i in range(0, 32, 4))

# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)

    hardware_length = int(hex_data[8:10], 16)
    protocol_length = int(hex_data[10:12], 16)
    operation = int(hex_data[12:16], 16)

    sender_hardware_address_hex = hex_data[16:28]
    sender_hardware_address = format_mac(sender_hardware_address_hex)
    sender_protocol_address_hex = hex_data[28:36]
    sender_protocol_address = format_ip(sender_protocol_address_hex)

    target_hardware_address_hex = hex_data[36:48]
    target_hardware_address = format_mac(target_hardware_address_hex)
    target_protocol_address_hex = hex_data[48:56]
    target_protocol_address = format_ip(target_protocol_address_hex)

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")

    print(f"  {'Hardware Length:':<25} {hex_data[8:10]:<20} | {hardware_length}")
    print(f"  {'Protocol Length:':<25} {hex_data[10:12]:<20} | {protocol_length}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")

    print(f"  {'Sender Hardware Address:':<25} {hex_data[16:28]:<20} | {sender_hardware_address}")
    print(f"  {'Sender Protocol Address:':<25} {hex_data[28:36]:<20} | {sender_protocol_address}")

    print(f"  {'Target Hardware Address:':<25} {hex_data[36:48]:<20} | {target_hardware_address}")
    print(f"  {'Target Protocol Address:':<25} {hex_data[48:56]:<20} | {target_protocol_address}")

    # print(f"\ntest:{protocol_type}\n")

def parse_ipv4_header(hex_data):
    version = int(hex_data[:1], 16)
    header_length = int(hex_data[1:2], 16)
    type_of_service = int(hex_data[2:4], 16)
    total_length = int(hex_data[4:8], 16)

    identification = int(hex_data[8:12], 16)
    flags_and_fragment_offset = int(hex_data[12:16], 16)
    flags_and_fragment_offset_bin = f'{flags_and_fragment_offset:0{16}b}' 

    time_to_live = int(hex_data[16:18], 16)
    protocol = int(hex_data[18:20], 16)
    header_checksum = int(hex_data[20:24], 16)

    source_address_hex = hex_data[24:32]
    source_address = format_ip(source_address_hex)
    destination_address_hex = hex_data[32:40]
    destination_address = format_ip(destination_address_hex)

    total_header_length = header_length * 8
    options = "N/A"
    if header_length > 5:
        options = hex_data[40:total_header_length]

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[:1]:<20} | {version}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {header_length} bytes")
    print(f"  {'Type of Service:':<25} {hex_data[2:4]:<20} | {type_of_service}")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length} bytes")

    print(f"  {'Identification:':<25} {hex_data[8:12]:<20} | {identification}")
    print(f"  {'Flags & Fragment Offset':<25} {hex_data[12:16]:<20} | {flags_and_fragment_offset}")
    print(f"    {'Reserved':<28} {flags_and_fragment_offset_bin[:1]:<15}")
    print(f"    {'DF (Do not Fragment)':<28} {flags_and_fragment_offset_bin[1:2]:<15}")
    print(f"    {'MF (More Fragments)':<28} {flags_and_fragment_offset_bin[2:3]:<15}")
    print(f"    {'Fragment Offset':<28} {hex(int(flags_and_fragment_offset_bin[3:16], 2)):<15} | {int(flags_and_fragment_offset_bin[3:16], 2)}")

    print(f"  {'Time to Live:':<25} {hex_data[16:18]:<20} | {time_to_live}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Header Checksum:':<25} {hex_data[20:24]:<20} | {header_checksum}")

    print(f"  {'Source Address:':<25} {hex_data[24:32]:<20} | {source_address}")
    print(f"  {'Destination Address:':<25} {hex_data[32:40]:<20} | {destination_address}")

    print(f"  {'Options (hex):':<25} {options:<20}")

    payload = hex_data[total_header_length:]
    if protocol == 1:
        parse_icmpv4_header(payload)
        print("icmpv4\n")
    elif protocol == 6:
        # parse_tcp_header(hex_data)
        print("tcp ipv4\n")

    elif protocol == 17:
        # parse_udp_header(hex_data)
        print("udp ipv4\n")

    else:
        print(f"  {'Unknown protocol:':<25} {hex_data[18:20], 16:<20} | {protocol}")
        print("  No parser available for this protocol.")
    # print(f"\nhex stream:{hex_data}\n")
    # print(f"\nflag frag:{flags_and_fragment_offset}\n")
    # print(f"\nbin flag frag:{flags_and_fragment_offset_bin}\n")


def parse_ipv6_header(hex_data):
    version = int(hex_data[:1], 16)
    type_of_service = int(hex_data[1:3], 16)
    flow = int(hex_data[3:8], 16)

    payload_length = int(hex_data[8:12], 16)
    next_header = int(hex_data[12:14], 16)
    hop_limit = int(hex_data[14:16], 16)

    source_address_hex = hex_data[16:48]
    source_address = format_ipv6(source_address_hex)
    destination_address_hex = hex_data[48:80]
    destination_address = format_ipv6(destination_address_hex)

    # total_header_length = header_length * 8
    # options = "N/A"
    # if header_length > 5:
    #     options = hex_data[40:total_header_length]
    print(f"IPv6 Header:")
    print(f"  {'Version:':<25} {hex_data[:1]:<20} | {version}")
    print(f"  {'Type of Service:':<25} {hex_data[1:3]:<20} | {type_of_service}")
    print(f"  {'Flow':<25} {hex_data[3:8]:<20} | {flow}")

    print(f"  {'Payload Length:':<25} {hex_data[8:12]:<20} | {payload_length} bytes")
    print(f"  {'Next Header:':<25} {hex_data[12:14]:<20} | {next_header}")
    print(f"  {'Hop Limit:':<25} {hex_data[14:16]:<20} | {hop_limit}")
    
    print(f"  {'Source Address:':<25} {hex_data[16:48]:<20} | {source_address}")
    print(f"  {'Destination Address:':<25} {hex_data[48:80]:<20} | {destination_address}")

    print(f"\nhex stream:{hex_data}\n")

    payload = hex_data[80:]
    if next_header == 58:
        # parse_icmpv6_header(next_header_data)
        print("icmpv6")

    elif next_header == 6:
        # parse_tcp_header(hex_data)
        print("ipv6 tcp")

    elif next_header == 17:
        # parse_udp_header(hex_data)
        print("ipv6 udp")

    else:
        print(f"  {'Unknown protocol:':<25} {hex_data[12:14], 16:<20} | {next_header}")
        print("  No parser available for this protocol.")

# TODO: test by hand
def parse_icmpv4_header(hex_data):
    type_field = int(hex_data[:2], 16)
    code = int(hex_data[2:4], 16)
    checksum = int(hex_data[4:8], 16)

    payload = hex_data[8:16]

    print(f"ICMPv4 Header:")
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {type_field}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum':<25} {hex_data[4:8]:<20} | {checksum}")

    print(f"  {'Payload (hex):':<25} {hex_data[8:16]:<20}")

    print(f"\nhex stream:{hex_data}\n")

