from functions import *
import os
import subprocess


def addCapsInfos(pcap, out):
    info = subprocess.run(['capinfos', pcap], capture_output=True, text=True, check=True)

    with open(out, 'w') as file:
        file.write(info.stdout)


def main():
    # Trova le directories di tutti i file pcap e crea un file log associato
    pcaps = []
    outfiles = []
    infoFiles = []
    directories = os.listdir('../02_15_b2_00_00_00')
    for dir in directories:
        path = f'../02_15_b2_00_00_00/{dir}/traffic.pcap'
        pcaps.append(path)
        out_file = f'./logs/{dir}.log'
        outfiles.append(out_file)
        info = f'./capsInfos/{dir}.infos'
        infoFiles.append(info)

    # Analizza le tracce pcap e metti il risultato nei file log associati
    i = 1
    for pcap, out in zip(pcaps, outfiles):  
        print(f"Traccia {i}")
        analizzaPCAP(pcap, out)
        i += 1
    # Aggiungi i risultati di capinfos
    i = 1
    for pcap, out in zip(pcaps, infoFiles):
        print(f"CapInfos {i}")
        addCapsInfos(pcap, out)
        i += 1



if __name__ == '__main__':
    main()

    # Analizza un singolo pcap, per debug
    pcacp_speciale = '../02_15_b2_00_00_00/20231109215429/traffic.pcap'
    analizzaPCAP(pcacp_speciale, './out')
