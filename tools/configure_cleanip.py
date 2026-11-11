"""Configure the current Windows user's CleanIP key, never print the key."""
from pathlib import Path
import getpass,sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'src'))
from cleanip_credentials import save_key
if __name__=='__main__':
    save_key(getpass.getpass('CleanIP API key (hidden): '))
    print('CleanIP key encrypted for this Windows user. Restart NetMonitor or refresh IP quality.')
