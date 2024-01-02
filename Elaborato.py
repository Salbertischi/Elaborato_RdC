from functions import *
from manage_output import *
from pandas_fun import *
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
    out_dirs = []
    root_dir = r"./02_15_b2_00_00_00"
    directories = os.listdir(root_dir)
    
    for dir in directories:
        path = os.path.join(root_dir, f'{dir}/traffic.pcap')
        pcaps.append(path)
        
        out_dir = get_outDir(os.path.join(root_dir, dir))
        out_dirs.append(out_dir)
        
        out_file = os.path.join(out_dir, f'{dir}.log.txt')
        outfiles.append(out_file)        

        info = os.path.join(out_dir, f'{dir}.infos.txt')
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
        
    i = 1
    for outLog, outDir in zip(outfiles, out_dirs):
        dns_summary(outLog, outDir)
        ip_traffic_summary(outLog, outDir)
        sni_summary(outLog, outDir)
        i += 1
 


if __name__ == '__main__':
    main()

    # Analizza un singolo pcap, per debug
    #pcacp_speciale = '../02_15_b2_00_00_00/20231109215429/traffic.pcap'
    #analizzaPCAP(pcacp_speciale, './out')
