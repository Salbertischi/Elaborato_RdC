#commento azzo
from scapy.all import *
import whois
import csv


def get_whois_info(ip_address):
    try:
        # Esegui l'interrogazione WHOIS sull'indirizzo IP
        result = whois.whois(ip_address)
        return result
    except whois.parser.PywhoisError:
        return 'Eccezione'


def flow_tableToCSV(flow_table):
    output_csv = './out.log'
    with open(output_csv, mode='w', newline='') as csv_file:
        fieldnames = ['src_ip', 'dst_ip', 'sport', 'dport', 'packet_count', 'Query_DNS', 'Who_Is?']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Scrivi l'intestazione del file CSV
        writer.writeheader()

        # Scrivi i dati dei flussi nella tabella
        for flow_key, data in flow_table.items():
            writer.writerow({
                'src_ip': flow_key[0],
                'dst_ip': flow_key[1],
                'sport': flow_key[2],
                'dport': flow_key[3],
                'packet_count': len(data[0]),      # data[0] sarebbe packets
                'Query_DNS' : data[1],          # Query DNS se presente
                'Who_Is?' : data[2]
            })


def analyze_traffic(pcap_file):
    # Leggi il file di tracce di traffico
    packets = rdpcap(pcap_file)

    # Inizializza una tabella per i biflussi
    flow_table = {}

    # Analizza i pacchetti e costruisci la tabella dei biflussi
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = None
            dport = None

            # Gestisci il protocollo di trasporto (TCP, UDP)
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            # Costruisci l'identificatore del flusso
            flow_key = (src_ip, dst_ip, sport, dport)

            # Aggiungi il pacchetto al flusso corrispondente
            if flow_key not in flow_table:
                flow_table[flow_key] = [[]]

#TO DO: Finire roba dns
            if DNS in packet and packet[DNS].haslayer(DNSQR):
                dns_query = packet[DNS].qd.qname.decode('utf-8')
            else:
                dns_query = 'NoQueryDNS'
                
#TO DO: roba SNI

            flow_table[flow_key][0].append(packet)
            flow_table[flow_key].append(dns_query)
            flow_table[flow_key].append(get_whois_info(dst_ip))
    flow_tableToCSV(flow_table)
   
    # Stampa i risultati o esegui ulteriori analisi
    #for flow_key, packets in flow_table.items():
        #print(f"Flusso: {flow_key}, Numero di pacchetti: {len(packets)}")

    # Esempio: Calcola la dimensione totale del traffico per ciascun flusso
    #for flow_key, packets in flow_table.items():
        #total_size = sum(len(packet) for packet in packets)
        #print(f"Dimensione totale del traffico per il flusso {flow_key}: {total_size} byte")
    
