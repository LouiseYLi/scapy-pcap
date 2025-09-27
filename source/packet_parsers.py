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

    # print(f"\nhex stream:{hex_data}\n")
    # print(f"\ntest:{protocol_type}\n")


