from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.http import *
import whois
import csv
from functools import lru_cache


class Biflusso:
    def __init__(self, chiave):
        self.chiave = chiave            # IP1, IP2, Port1, Port2
        self.pacchetti = []             # Lista di pacchetti appartenenti a questo biflusso
        self.transportProtocol = ''     # Protocollo livello transporto
        self.queryDNS = []              # Lista di Query Answers, se presenti
        self.whoIs = []                 # Whois info su IP1 e IP2
        self.SNI = []                   # Campo SNI
        self.HTTP = []                  # Host HTTP contattato

    def numeroPacchetti(self):
        return len(self.pacchetti)

    def from1to2(self):
        IP1 = self.chiave[0]
        count = 0
        for pacchetto in self.pacchetti:
            if IP in pacchetto and pacchetto[IP].src == IP1:
                count += 1
        return count

    def from2to1(self):
        IP2 = self.chiave[1]
        count = 0
        for pacchetto in self.pacchetti:
            if IP in pacchetto and pacchetto[IP].src == IP2:
                count += 1
        return count

    def addQuery(self, query):
        self.queryDNS.append(query)
    
    def addSNI(self, SNI):
        self.SNI.append(SNI)
    
    def addHTTPHost(self, hostHTTP):
        self.HTTP.append(hostHTTP)
    
    def addWhoIs(self, whoIs):
        self.whoIs.append(whoIs)


def controllaDNS(packet):
    if DNS in packet and packet[DNS].qr == 1:
        protocols = packet[IP].proto
        if DNSRR in packet and DNSQR in packet:
            dnsAnswer = []
            dnsQueryName = None
            try:
                i = 0
                # Usare un for per scorrere la lista packet[DNSRR] dava solo il primo elemento
                while True:
                    dnsAnswer.append(packet[DNSRR][i].rdata)
                    i += 1
            except IndexError:
                pass
            dnsQueryName = packet[DNS].qd.qname.decode('utf-8')
            return  {
                    'Protocols': protocols,
                    'DNS Answer': dnsAnswer,
                    'DNS Query Name': dnsQueryName
                    }
    return None


def controllaSNI(packet):
    SNI = None
    try:
        if TLS in packet:
            SNI = packet[ServerName].servername.decode('utf-8')
    except:
        SNI = None
    return SNI


def controllaHostHTTP(packet):
    HTTP = None
    try:
        if HTTPRequest in packet:
            HTTP = packet[HTTPRequest].Host.decode()
    except:
        HTTP = None
    return HTTP


@lru_cache(maxsize=None)
def WhoIsInfo(ip):
    try:
        result = whois.whois(ip)
        return result
    except Exception:
        return 'Eccezione'


def stampaSuCSV(biflussi, outFile):
    with open(outFile, mode='w', newline='') as csv_file:
        fieldnames = ['IP1', 'IP2', 'Port1', 'Port2', 'Transport_Protocol', 'packet_count', 'From1to2', 'From2to1', 'Query_DNS', 'Who_Is', 'SNI', 'HTTP']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        # Scrivi l'intestazione del file CSV
        writer.writeheader()

        # Scrivi i dati dei flussi nella tabella
        for chiave, biflusso in biflussi.items():
            writer.writerow({
                'IP1': chiave[0],
                'IP2': chiave[1],
                'Port1': chiave[2],
                'Port2': chiave[3],
                'Transport_Protocol': biflusso.transportProtocol,
                'packet_count': biflusso.numeroPacchetti(),
                'From1to2': biflusso.from1to2(),
                'From2to1': biflusso.from2to1(),
                'Query_DNS' : [q for q in biflusso.queryDNS],          
                'Who_Is' : [w for w in biflusso.whoIs],
                'SNI' : [s for s in biflusso.SNI],
                'HTTP' : [h for h in biflusso.HTTP]
            })


def analizzaPCAP(pcapFile, outFile):
    packets = rdpcap(pcapFile)

    biflussi = {}

    for packet in packets:
        if IP in packet:
            srcIP = packet[IP].src
            dstIP = packet[IP].dst
            srcPort = None
            dstPort = None

            tranProtocol = ''
            if TCP in packet:
                tranProtocol = 'TCP'
                srcPort = packet[TCP].sport
                dstPort = packet[TCP].dport
            elif UDP in packet:
                tranProtocol = 'UDP'
                srcPort = packet[UDP].sport
                dstPort = packet[UDP].dport
            
            chiaveBiflusso = (srcIP, dstIP, srcPort, dstPort)
            chiaveBiflussoAlt = (dstIP, srcIP, dstPort, srcPort)

            # Se ho già un biflusso con una chiave simmetrica non aggiungo un nuovo biflusso alla lista
            if chiaveBiflussoAlt in biflussi.keys():
                chiaveBiflusso = chiaveBiflussoAlt
            
            # Se ho una nuova chiave aggiungo un biflusso
            if chiaveBiflusso not in biflussi.keys():
                biflussi[chiaveBiflusso] = Biflusso(chiaveBiflusso)

            biflussi[chiaveBiflusso].transportProtocol = tranProtocol
            biflussi[chiaveBiflusso].pacchetti.append(packet)
            
            query = controllaDNS(packet)
            if query is not None:
                biflussi[chiaveBiflusso].addQuery(query)
            
            SNI = controllaSNI(packet)
            if SNI is not None:
                biflussi[chiaveBiflusso].addSNI(SNI)

            hostHTTP = controllaHostHTTP(packet)
            if hostHTTP is not None:
                biflussi[chiaveBiflusso].addHTTPHost
    
    for chiave in biflussi.keys():
        biflussi[chiave].addWhoIs(WhoIsInfo(chiave[0]))
        biflussi[chiave].addWhoIs(WhoIsInfo(chiave[1]))
    
    stampaSuCSV(biflussi, outFile)
