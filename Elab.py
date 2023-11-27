from func import *


def main():
    analyze_traffic('../02_15_b2_00_00_00/20231109215429/traffic.pcap')


if __name__ == '__main__':
    main()



'''
 if DNS in packet and packet[DNS].haslayer(DNSQR):
                dns_query = packet[DNS].qd.qname.decode('utf-8')
                #print(f"Risoluzione DNS nel pacchetto: {dns_query}")
            else:
                dns_query = 'NO_Q_DNS'
            if DNS in packet and packet[DNS].ns:
                for ns_record in packet[DNS].ns:
                    if ns_record.type in {1, 28}:  # 1 corrisponde a A, 28 corrisponde a AAAA
                        dns_ip = ns_record.rdata
                        dns_query += dns_ip   

'''