import pandas as pd
import pickle
from tqdm import tqdm
from pathlib import Path

df_length = pd.DataFrame()
df_time = pd.DataFrame()


RESULT_DIR = Path('results')

result_dirs = sorted(RESULT_DIR.iterdir())
pbar = tqdm(result_dirs)

for result_dir in pbar:
    key_size = result_dir.stem

    try:
        with open(result_dir / 'client.pkl', 'rb') as f:
            client_results = pickle.load(f)
        with open(result_dir / 'server.pkl', 'rb') as f:
            server_results = pickle.load(f)
    except:
        continue

    for k, v in client_results['length'].items():
        df_length.loc[key_size, k] = v

    for k, v in server_results['length'].items():
        df_length.loc[key_size, k] = v

    for k, v in client_results['time'].items():
        df_time.loc[key_size, k] = v

    for k, v in server_results['time'].items():
        df_time.loc[key_size, k] = v
