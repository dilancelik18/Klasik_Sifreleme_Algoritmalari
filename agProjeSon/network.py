from scapy.all import*
from pyvis.network import Network
import networkx as nx
import matplotlib.pyplot as plt

def ip_to_int(ip):
    # IP adresini dört ayrı sayıya böler ve bunları birleştirerek bir tamsayıya çevirir
    octets = list(map(int, ip.split('.')))
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]

def are_same_network(ip1, ip2, subnet_mask):
    # IP adreslerini sayısal değerlere çevir
    ip1_int = ip_to_int(ip1)
    ip2_int = ip_to_int(ip2)
    subnet_mask_int = ip_to_int(subnet_mask)

    # IP adreslerini ağ maskesine göre kontrol et
    return (ip1_int & subnet_mask_int) == (ip2_int & subnet_mask_int)

def find_devices_in_same_network(pcap_file):
    # Pcap dosyasını yükle
    packets = rdpcap(pcap_file)

    # Pcap dosyasındaki tüm paketlere uygula
    for i in range(len(packets)-1):
        current_packet_ip = packets[i][IP].src
        next_packet_ip = packets[i+1][IP].src

        # Ağ maskesini al
        subnet_mask = packets[i][IP].dst

        # İki cihazın aynı ağda olup olmadığını kontrol et
        if are_same_network(current_packet_ip, next_packet_ip, subnet_mask):
            print(f"Paket {current_packet_ip} ve Paket {next_packet_ip}: İki cihaz aynı ağda.")
        else:
            print(f"Paket {current_packet_ip} ve Paket {next_packet_ip}: İki cihaz farklı ağlarda.")
            find_routers_traversed(pcap_file)


def check_vlan(pcap_file):
    # Pcap dosyasını yükle
    packets = rdpcap(pcap_file)

    # Her paketi kontrol et
    for i, packet in enumerate(packets):
        # VLAN etiketleri olan paketleri filtrele
        vlan_layers = packet.layers().__contains__(Dot1Q)
        if vlan_layers:
            vlan_tags = [layer.vlan for layer in packet if Dot1Q in layer]
            print(f"Paket {i + 1}: VLAN etiketleri: {vlan_tags}")

def find_routers_traversed(pcap_file):
    # Pcap dosyasını yükle
    packets = rdpcap(pcap_file)

    # Her paketi kontrol et
    for i, packet in enumerate(packets):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl

            # TTL değerini kontrol et
            print(f"Paket {i + 1}: {src_ip} --> {dst_ip}, TTL: {ttl}")

def find_unique_routers(pcap_file):
    # Pcap dosyasını yükle
    packets = rdpcap(pcap_file)

    unique_routers = set()
    G = nx.Graph()
    # Her paketi kontrol et
    for i, packet in enumerate(packets):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ttl = packet[IP].ttl

            # TTL değerini kontrol et
            if ttl < 64:  # Örnek olarak, TTL değeri 64'ten küçükse bir router'dan geçmiş olabilir
                unique_routers.add(src_ip)

    print(f"Farklı router sayısı: {len(unique_routers)}")
    print("Router IP Adresleri:")
    for router_ip in unique_routers:
        print(router_ip)
        G.add_node(router_ip)
        if(src_ip!=router_ip):
            G.add_edge(src_ip, router_ip)

        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, font_size=8, node_size=300, node_color='red', font_color='black',
                font_family='arial')

        # Görselleştirmeyi kaydet
        plt.savefig("network_topology.png")
        plt.show()

def analyze_firewall(pcap_file):
    # Pcap dosyasını yükle
    packets = rdpcap(pcap_file)

    # ICMP paketleri üzerinden firewall analizi
    icmp_packets = [pkt for pkt in packets if ICMP in pkt]
    if len(icmp_packets) > 0:
        print("ICMP paketleri bulundu. Firewall ICMP engellemesi olabilir.")

    # TCP ve UDP paketleri üzerinden firewall analizi
    tcp_packets = [pkt for pkt in packets if TCP in pkt]
    udp_packets = [pkt for pkt in packets if UDP in pkt]

    if len(tcp_packets) > 0 or len(udp_packets) > 0:
        print("TCP veya UDP paketleri bulundu. Firewall TCP veya UDP engellemesi olabilir.")

    # Port tarama aktiviteleri üzerinden firewall analizi
    dest_ports = set(pkt[IP].dport for pkt in packets if IP in pkt)
    if len(dest_ports) > 10:
        print("Birçok farklı hedef porta yapılan bağlantılar. Port tarama aktivitesi olabilir.")


def find_ttl_differences(pcap_file):
    # Pcap dosyasını yükle
    packets = rdpcap(pcap_file)

    # Aynı kaynak ve hedef IP'ye sahip paketlerin TTL farkını kontrol et
    for i in range(len(packets)-1):
        current_packet = packets[i]
        next_packet = packets[i+1]

        if IP in current_packet and IP in next_packet:
            current_src_ip = current_packet[IP].src
            current_dst_ip = current_packet[IP].dst
            current_ttl = current_packet[IP].ttl

            next_src_ip = next_packet[IP].src
            next_dst_ip = next_packet[IP].dst
            next_ttl = next_packet[IP].ttl

            # Aynı kaynak ve hedef cihaz arasındaki TTL farkını kontrol et
            if current_src_ip == next_src_ip and current_dst_ip == next_dst_ip:
                ttl_difference = abs(current_ttl - next_ttl)
                print(f"Paket {i + 1} ve {i + 2}: TTL Farkı = {ttl_difference}")

def find_internet_gateway(pcap_file):
    # Pcap dosyasını yükle
    packets = rdpcap(pcap_file)

    # Kaynak ve hedef IP adreslerini depolamak için küme oluştur
    source_ips = set()
    destination_ips = set()

    # Her paketi kontrol et
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Kaynak ve hedef IP adreslerini kümelere ekleyin
            source_ips.add(src_ip)
            destination_ips.add(dst_ip)

    # Ağ geçidi, yani internete çıkışı sağlayan IP adresini bulun
    internet_gateway = destination_ips - source_ips

    if internet_gateway:
        print("İnternet Gateway IP Adresi:", internet_gateway.pop())
    else:
        print("İnternet Gateway bulunamadı.")

def connect_with_switch(device1_ip, device2_ip):
    print(f"Connect {device1_ip} and {device2_ip} with a Switch.")

def connect_with_router(device1_ip, device2_ip):
    print(f"Connect {device1_ip} and {device2_ip} with a Router.")

def visualize_network_connections(pcap_file):
    G = nx.Graph()

    packets = rdpcap(pcap_file)
    last_device = None

    for i in range(len(packets)-1):
        current_packet_ip = packets[i][IP].src
        next_packet_ip = packets[i+1][IP].src
        subnet_mask = packets[i][IP].dst

        if are_same_network(current_packet_ip, next_packet_ip, subnet_mask):
            if last_device is not None:
                G.add_node(last_device, node_type='Host')
                G.add_edge(last_device, current_packet_ip, connection_type='Switch')
                last_device = None
            else:
                last_device = current_packet_ip
        else:
            G.add_node(current_packet_ip, node_type='Host')
            G.add_edge(current_packet_ip, next_packet_ip, connection_type='Router')
            last_device = None

    # Son paketi işleme
    if last_device is not None:
        G.add_node(last_device, node_type='Host')

    pos = nx.spring_layout(G, seed=42, iterations=200, scale=100)
    node_colors = ['orange' if node_type != 'Router' else 'skyblue' for node_type in nx.get_node_attributes(G, 'node_type').values()]
    edge_labels = {(u, v): d['connection_type'] for u, v, d in G.edges(data=True)}

    nx.draw(G, pos, with_labels=True, font_size=8, node_size=300, node_color=node_colors, font_color='black',
            font_family='arial', width=2, edge_color='gray', alpha=0.7)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.savefig("network_connections.png")
    plt.show()


def detect_device_type(ip_address):
    # IP adresinin türünü tespit etmek için nmap kullanılır
       

            result = subprocess.run(['nmap', '-O', ip_address], capture_output=True, text=True)
            output = result.stdout
            device_type = re.search(r"Device type: (.+)", output).group(1)
            if "general purpose" in device_type.lower():
                return "Host"
            elif "router" in device_type.lower():
                return "Router"
            elif "switch" in device_type.lower():
                return "Switch"
            else:
                return "Unknown"

def visualize_network_topology(pcap_file):
    G = nx.Graph()

    packets = rdpcap(pcap_file)
    routers = set()

    for i in range(len(packets) - 1):
        current_packet_ip = packets[i][IP].src
        next_packet_ip = packets[i + 1][IP].src
        subnet_mask = packets[i][IP].dst

        if are_same_network(current_packet_ip, next_packet_ip, subnet_mask):
            G.add_edge(current_packet_ip, next_packet_ip)
        else:
            # Farklı ağlardaysa, bir router olarak düşünüp grafikte birleştiriyoruz.
            router_ip = f"Router_{len(routers) + 1}"
            G.add_node(router_ip, node_type='Router')
            G.add_edge(current_packet_ip, router_ip)
            G.add_edge(router_ip, next_packet_ip)
            routers.add(router_ip)

    pos = nx.spring_layout(G, seed=42)  # seed kullanarak pozisyonları sabit tutuyoruz
    node_colors = ['skyblue' if node_type != 'Router' else 'orange' for node_type in
                   nx.get_node_attributes(G, 'node_type').values()]

    nx.draw(G, pos, with_labels=True, font_size=8, node_size=300, node_color=node_colors, font_color='black',
            font_family='arial')

    plt.savefig("network_topology_with_routers.png")
   # plt.show()

# Kullanım
def measure_bandwidth(pcap_file):
    packets = rdpcap(pcap_file)
    total_bytes = 0
    start_time = packets[0].time
    end_time = packets[-1].time

    for packet in packets:
        total_bytes += len(packet)

    duration = end_time - start_time
    bandwidth = total_bytes / duration

    return bandwidth

def find_dhcp_servers():
    # DHCP Discover paketi oluştur
    dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr="00:00:0c:9f:f0:29") / DHCP(options=[("message-type", "discover"), "end"])

    # DHCP Discover paketini gönder ve cevapları al
    responses, _ = srp(dhcp_discover, timeout=2, verbose=0)

    # Cevapları işle
    dhcp_servers = set()
    for response in responses:
        if response[1][DHCP].options[0][1] == 2:  # 2: DHCPOffer
            dhcp_servers.add(response[1][IP].src)

    return dhcp_servers

def analyze_protocols(pcap_file):
    # PCAP dosyasını aç
    packets = rdpcap(pcap_file)

    # Protokollerin sayısını ve adlarını tutacak bir sözlük oluştur
    protocol_count = {}

    # Paketleri döngüye alarak protokollerin sayısını ve adlarını tespit et
    for packet in packets:
        # Ethernet paketi içerisindeki üst katman protokolü
        protocol = packet[0].name

        # Protokolü sözlüğe ekle veya sayısını artır
        if protocol in protocol_count:
            protocol_count[protocol] += 1
        else:
            protocol_count[protocol] = 1

    # Analiz sonuçlarını ekrana yazdır
    print("Protokollerin Sayısı ve Adları:")
    for protocol, count in protocol_count.items():
        print(f"{protocol}: {count} adet")

def analyze_transport_protocols(pcap_file):
    # PCAP dosyasını aç
    packets = rdpcap(pcap_file)

    # Transport layer protokollerini tutacak bir sözlük oluştur
    transport_protocols = {}

    # Paketleri döngüye alarak transport layer protokollerini tespit et
    for packet in packets:
        # IP paketi içerisindeki transport layer protokolü
        if IP in packet:
            transport_protocol = packet[IP].payload.name

            # Transport layer protokolünü sözlüğe ekle veya sayısını artır
            if transport_protocol in transport_protocols:
                transport_protocols[transport_protocol] += 1
            else:
                transport_protocols[transport_protocol] = 1

    # Analiz sonuçlarını ekrana yazdır
    print("Transport Layer Protokollerinin Sayısı ve Adları:")
    for protocol, count in transport_protocols.items():
        print(f"{protocol}: {count} adet")


def analyze_all_protocols_with_names(pcap_file):
    # PCAP dosyasını aç
    packets = rdpcap(pcap_file)

    # Tüm katman protokollerini ve adlarını tutacak bir liste oluştur
    all_protocols = []

    # Paketleri döngüye alarak tüm katman protokollerini tespit et
    for packet in packets:
        # Paketin içindeki tüm katman protokollerini ekleyin
        packet_protocols = [layer.name for layer in packet.layers()]
        all_protocols.append(packet_protocols)

    # Analiz sonuçlarını ekrana yazdır
    print("Tüm Katman Protokollerinin ve Adlarının Listesi:")
    for i, packet_protocols in enumerate(all_protocols, start=1):
        print(f"Paket {i}: {packet_protocols}")





pcap_file_path = "C:\\Users\\Dilce\\OneDrive\\Masaüstü\\pcapfile.pcap"
analyze_firewall(pcap_file_path)
find_devices_in_same_network(pcap_file_path)
check_vlan(pcap_file_path)
find_unique_routers(pcap_file_path)
find_ttl_differences(pcap_file_path)
find_internet_gateway(pcap_file_path)
#visualize_network_topology(pcap_file_path)
visualize_network_connections(pcap_file_path)
try:
        bandwidth = measure_bandwidth(pcap_file_path)
        print(f"Bant genişliği kullanımı: {bandwidth:.2f} byte/saniye")
except Exception as e:
        print(f"Hata: {e}")

try:
        dhcp_servers = find_dhcp_servers()
        if dhcp_servers:
            print("Bulunan DHCP Sunucuları:")
            for server in dhcp_servers:
                print(f"  - {server}")
        else:
            print("Ağda DHCP Sunucu bulunamadı.")
except Exception as e:
        print(f"Hata: {e}")

analyze_protocols(pcap_file_path)
analyze_transport_protocols(pcap_file_path)
