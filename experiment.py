import time
import pickle
import multiprocessing
import numpy as np
from tqdm import tqdm
from pathlib import Path

from dhcp_sever import DHCPServer
from dhcp_client import DHCPClient 


RESULT_DIR = Path('results')
KEY_SIZE_MIN = 2048
KEY_SIZE_MAX = 4096 
SLEEP_TIME = 1.0


def generate_server_process(key_size):
    result_path = RESULT_DIR / f'{key_size}/server.pkl'
    result_path.parent.mkdir(parents=True, exist_ok=True)

    server_ip = '172.17.0.2'
    ca_asset_dir = 'certificates/rootCA/2048'
    ca_asset_name = 'rootCA'
    my_asset_dir = f'certificates/server/{key_size}'
    my_asset_name = 'server'
    server = DHCPServer(
            server_ip=server_ip,
            ca_asset_dir=ca_asset_dir,
            ca_asset_name=ca_asset_name,
            my_asset_dir=my_asset_dir,
            my_asset_name=my_asset_name,
            )
    length_dict, time_dict = server.start()
    with open(result_path, 'wb') as f:
        pickle.dump({
            'length': length_dict,
            'time': time_dict,
            },
            f,
            )

def generate_client_process(key_size):
    result_path = RESULT_DIR / f'{key_size}/client.pkl'
    result_path.parent.mkdir(parents=True, exist_ok=True)

    server_ip = '<broadcast>'
    ca_asset_dir = 'certificates/rootCA/2048'
    ca_asset_name = 'rootCA'
    my_asset_dir = None 
    my_asset_name = None 
    client = DHCPClient(
            server_ip=server_ip,
            ca_asset_dir=ca_asset_dir,
            ca_asset_name=ca_asset_name,
            my_asset_dir=my_asset_dir,
            my_asset_name=my_asset_name,
            )
    length_dict, time_dict = client.start()
    with open(result_path, 'wb') as f:
        pickle.dump({
            'length': length_dict,
            'time': time_dict,
            },
            f,
            )

def experiment(key_size):
    server_result_path = RESULT_DIR / f'{key_size}/server.pkl'
    client_result_path = RESULT_DIR / f'{key_size}/client.pkl'
    if server_result_path.exists() and client_result_path:
        return

    procs = []

    p = multiprocessing.Process(target=generate_server_process, args=(key_size, ))
    p.daemon = False  # Set daemon attribute to False
    p.start()
    procs.append(p)

    time.sleep(SLEEP_TIME)

    p = multiprocessing.Process(target=generate_client_process, args=(key_size, ))
    p.daemon = False  # Set daemon attribute to False
    p.start()
    procs.append(p)

    for p in procs:
        p.join()  


if __name__ == '__main__':
    key_sizes = range(KEY_SIZE_MIN, KEY_SIZE_MAX)
    #key_sizes = np.split(np.array(key_sizes), 4, 0)[1]

    # from multiprocessing import Pool
    # with Pool(2) as pool:
    #     pool.map(experiment, key_sizes)

    pbar = tqdm(key_sizes)
    for key_size in pbar: 
        experiment(key_size)
