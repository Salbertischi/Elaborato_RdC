from functions import *
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
    i = 1
    for pcap, out in zip(pcaps, outfiles):  
        print(f"Traccia {i}")
        analizzaPCAP(pcap, out)
        i += 1


if __name__ == '__main__':
    main()

    # Analizza un singolo pcap, per debug
    pcacp_speciale = '../02_15_b2_00_00_00/20231109215429/traffic.pcap'
    analizzaPCAP(pcacp_speciale, './out')
