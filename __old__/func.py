from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.http import *
import whois
import csv
from functools import lru_cache
import Dati.Dati


class Dati:
    def __init__(self):
        self.chiave = ()
        self.pacchetti = []
        self.transportProtocol = ''
        self.QueryDNS = []
        self.WhoIs = []
        self.SNI = []
        self.HTTP = []

    def from1to2(self):
        count = 0
        for pacchetto in self.pacchetti:
            if IP in pacchetto and pacchetto[IP].src == self.chiave[0]:
                count += 1
        return count

    def from2to1(self):
        count = 0
        for pacchetto in self.pacchetti:
            if IP in pacchetto and pacchetto[IP].src == self.chiave[1]:
                count += 1
        return count
        

@lru_cache(maxsize=None)
def get_whois_info(ip):
    try:
        # Esegui l'interrogazione WHOIS sull'indirizzo IP
        result = whois.whois(ip)
        return result
    except whois.parser.PywhoisError:
        return 'Eccezione'


def flow_tableToCSV(flow_table, out_file):
    output_csv = out_file
    with open(output_csv, mode='w', newline='') as csv_file:
        fieldnames = ['IP1', 'IP2', 'Port1', 'Port2', 'Transport_Protocol', 'packet_count', 'From1to2', 'From2to1', 'Query_DNS', 'Who_Is', 'SNI', 'HTTP']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Scrivi l'intestazione del file CSV
        writer.writeheader()

        # Scrivi i dati dei flussi nella tabella
        for flow_key, data in flow_table.items():
            writer.writerow({
                'IP1': flow_key[0],
                'IP2': flow_key[1],
                'Port1': flow_key[2],
                'Port2': flow_key[3],
                'Transport_Protocol': data.transportProtocol,
                'packet_count': len(data.pacchetti),
                'From1to2': data.from1to2(),
                'From2to1': data.from2to1(),
                'Query_DNS' : [q for q in data.QueryDNS],          
                'Who_Is' : [w for w in data.WhoIs],
                'SNI' : [s for s in data.SNI],
                'HTTP' : [h for h in data.HTTP]
            })


def analyze_traffic(pcap_file, out_file):
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

            TranProtocol = ''
            # Gestisci il protocollo di trasporto (TCP, UDP)
            if TCP in packet:
                TranProtocol = 'TCP'
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                TranProtocol = 'UDP'
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            # Costruisci l'identificatore del flusso
            flow_key = (src_ip, dst_ip, sport, dport)
            alt_flow_key = (dst_ip, src_ip, dport, sport)
            if alt_flow_key in flow_table.keys():
                flow_key = alt_flow_key

            # Aggiungi il pacchetto al flusso corrispondente
            if flow_key not in flow_table:
                flow_table[flow_key] = Dati()

            # Roba DNS
            if DNS in packet and packet[DNS].qr == 1:
                protocols = packet[IP].proto
                if DNSRR in packet[DNS]:
                    dns_answer = packet[DNS].an.rdata
                else:
                    dns_answer = None
                if DNSQR in packet[DNS]:
                    dns_query_name = packet[DNS].qd.qname.decode('utf-8')  
                else:
                    dns_query_name = None
                flow_table[flow_key].QueryDNS.append({
                                                'Protocols': protocols,
                                                'DNS Answer': dns_answer,
                                                'DNS Query Name': dns_query_name
                                                })
            #TO DO: roba SNI
            
            SNI = None
            try:
                if TLS in packet:
                    SNI = packet[ServerName].servername.decode('utf-8')
                    #SNI = packet[TLS][TLS_Ext_ServerName].servernames[:]
                    # print(SNI)
                    #packet[handshake].type
            except:
                SNI = None
                pass

            #TO DO: roba HTTP.HOST
            HTTP = None
            try:
                if HTTPRequest in packet:
                    HTTP = packet[HTTPRequest].Host.decode()
                    # print(HTTP)
            except:
                HTTP = None

            
            #Aggiungi i risultati alla tabella
            flow_table[flow_key].chiave = flow_key
            flow_table[flow_key].pacchetti.append(packet)
            flow_table[flow_key].transportProtocol = TranProtocol
            if SNI:
                flow_table[flow_key].SNI.append(SNI) 
            if HTTP:
                flow_table[flow_key].HTTP.append(HTTP)
    
    for key, item in flow_table.items():
        flow_table[key].WhoIs.append(get_whois_info(key[0]))
        flow_table[key].WhoIs.append(get_whois_info(key[1]))
    
    flow_tableToCSV(flow_table, out_file)
   
    # Stampa i risultati o esegui ulteriori analisi
    #for flow_key, packets in flow_table.items():
        #print(f"Flusso: {flow_key}, Numero di pacchetti: {len(packets)}")

    # Calcola la dimensione totale del traffico per ciascun flusso
    #for flow_key, packets in flow_table.items():
        #total_size = sum(len(packet) for packet in packets)
        #print(f"Dimensione totale del traffico per il flusso {flow_key}: {total_size} byte")
    
