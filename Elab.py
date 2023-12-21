from func import *
import os


def main():
    # Trova le directories di tutti i file pcap e crea un file log associato
    pcaps = []
    outfiles = []
    directories = os.listdir('../02_15_b2_00_00_00')
    for dir in directories:
        path = f'../02_15_b2_00_00_00/{dir}/traffic.pcap'
        pcaps.append(path)
        out_file = f'./logs/{dir}.log'
        outfiles.append(out_file)

    # Analizza le tracce pcap e metti il risultato nei file log associati
    for pcap, out in zip(pcaps, outfiles):  
        analyze_traffic(pcap, out)


if __name__ == '__main__':
    load_layer("tls")
    #main()

    # Analizza un singolo pcap, per debug
    pcacp_speciale = '../02_15_b2_00_00_00/20231109215429/traffic.pcap'
    analyze_traffic(pcacp_speciale, './outSpeciale')
