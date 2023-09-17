"""
Objective is to take a network range, scan for open smb ports and enumerate them for username and passwords
"""


from sys import argv
import ipaddress
import socket



def main(network: str):
    """
    scan a subnet, find targets with open smb ports, attempt to enumerate unprotected shares
    """
    try:
        # get the provided ip block and convert to ipaddress object
        target = ipaddress.ip_network(network, strict=False)
        for ip in target.hosts():
            print(ip)
            # check here if all the hosts in the provided network range are listening for smb connections
    except ValueError as invalid_ip_block:
        print(f"Error:\n{invalid_ip_block}")


    

    



if __name__ == "__main__":
    print(r"""
               _
              | |
 ___ _ __ ___ | |__  ___  ___ __ _ _ __
/ __| '_ ` _ \| '_ \/ __|/ __/ _` | '_ \
\__ \ | | | | | |_) \__ \ (_| (_| | | | |
|___/_| |_| |_|_.__/|___/\___\__,_|_| |_|""""\n")

    try:
        network = argv[1]
        main(network)
    except IndexError as missing_argument:
        print("A network block argument in CIDR notation is required, example:\n$ smbscanner.py 10.0.0.0/24")
