import pandas as pd
import os

def dns_summary(csv_log_file, out_dir):
    log = pd.read_csv(csv_log_file)
    log = log[(log["Query_DNS"] != "[]") & (~log["Query_DNS"].str.contains("google|gstatic|android"))]
    DNS = log["Query_DNS"]
    name = csv_log_file.split('/')[3].split('.')[0]
    DNS.to_csv(os.path.join(out_dir, f'{name}_DNS_resolutions.txt'), index=False)
    
def get_DNS_server(log):
    log = log[log["Query_DNS"]!="[]"]
    log = log.groupby("IP2").first().reset_index()["IP2"]
    return log

def ip_traffic_summary(csv_log_file, out_dir):
    log = pd.read_csv(csv_log_file)
    log["Port2"] = log["Port2"].fillna(0).astype(int)
    
    DNS_server = get_DNS_server(log).tolist()
    log = log[(log["Port2"]!= 0) & (log["Port2"]!= 68) &(log["Port2"]!= 67) & (~log["SNI"].apply(lambda x: x.lower()).str.contains("google|gstatic")) & (~log["IP2"].isin(DNS_server))]
    ip_traffic = log.groupby("IP2", as_index=False).first()[["IP2", "Port2", "Transport_Protocol"]]
    name = csv_log_file.split('/')[3].split('.')[0]
    ip_traffic.to_csv(os.path.join(out_dir, f'{name}_IP_traffic.txt'), index=False)


def sni_summary(csv_log_file, out_dir):
    log = pd.read_csv(csv_log_file)
    log = log[log["SNI"]!="[]"]
    SNI = log["SNI"]
    name = csv_log_file.split('/')[3].split('.')[0]
    SNI.to_csv(os.path.join(out_dir, f'{name}_SNI.txt'), index=False)
