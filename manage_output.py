import os

def is_manual(directoryCattura):
    filepath = os.path.join(directoryCattura, 'info_capture.txt')
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            for line in file:
                if 'manual=True' in line:
                    return 1
    return -1

def get_hash(directoryCattura):
    hash = 'ciao'
    filepath = os.path.join(directoryCattura, 'hash_file.txt')
    if os.path.exists(filepath):
        with open(filepath, 'r') as file:
            for line in file:
                if line != '':
                    hash = line
    return hash

def get_outDir(directoryCattura):
    hash_value = get_hash(directoryCattura)
    hash_folder = os.path.join('.', hash_value)
    os.makedirs(hash_folder, exist_ok=True)
    
    if is_manual(directoryCattura)==1:
        out_dir = os.path.join(hash_folder, 'MANUAL')
    elif is_manual(directoryCattura)==-1:
        out_dir = os.path.join(hash_folder, 'AUTOMATIC')
    else:
        out_dir = os.path.join(hash_folder, 'ERRORE')
    os.makedirs(out_dir, exist_ok=True)
    
    return out_dir

