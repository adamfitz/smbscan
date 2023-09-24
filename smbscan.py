"""
Objective is to take a network range, scan for open smb ports and enumerate them for username and passwords
"""


from sys import argv
import ipaddress
import socket

import tqdm
from smb.SMBConnection import SMBConnection


def enumerate_shares(username='guest', password="", port_445=None):
    """
    Function to enumerate a list of target IPs for smb shares.

    By default connections are attempted with the guest user and no password, to find open shares.
    """

    for target in port_445:
        try:
            smbconnect = SMBConnection(username,
                                    password,
                                    is_direct_tcp=True,
                                    my_name='test_client',
                                    remote_name=socket.gethostbyname(target))
            assert smbconnect.connect(target, 445, timeout=10)
            share_list = smbconnect.listShares()
            for i in share_list:
                print(f"Sharename: {i.name}")
        except AssertionError as assert_error:
            print(f"Cannot list shares from {target} on port: {445}")
            pass







def main(network: str):
    """
    scan a subnet, find targets with open smb ports, attempt to enumerate unprotected shares
    """

    smb_ports = [139, 445]
    open_targets_p139 = []
    open_targets_p445 = []

    try:
        # get the provided ip block and convert to ipaddress object
        address_block = (ipaddress.ip_network(str(network), strict=False).hosts())

        # create a generator containing each IP as string
        hosts = map(str, address_block)

        # total hosts
        total_hosts = (ipaddress.ip_network(network).num_addresses) - 2

        # ouput
        print(f"Scanning Network:\t\t{network}")
        print(f"Total hosts to scan: \t\t{total_hosts}")
        print(f"Total scans ({len(smb_ports)} ports):\t\t{total_hosts * 2}")


        # iterate the target network or host
        with tqdm.tqdm(total=(total_hosts * 2)) as progress_bar:
            for ip in hosts:
            # iterate each port in the smb_ports list
                for port in smb_ports:
                    try:
                        # setup the connection
                        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                        # low timeout value so the script is quicker
                        connection.settimeout(1)

                        # attempt connection
                        connection.connect((ip, int(port)))

                        # port is open add target to the list
                        if port == 139:
                            machine_name = socket.gethostbyname(ip)
                            open_targets_p139.append(ip)
                        else:
                            machine_name = socket.gethostbyname(ip)
                            open_targets_p445.append(ip)

                    except socket.error as socket_error:
                        # update the progress bar manually when an error is raised.
                        progress_bar.update(1)
                        continue
                    finally:
                        # close connection after each connection attempt
                        connection.close()

        print(f"Targets listening on port 139:\n{open_targets_p139}\n")
        print(f"Targets listening on port 445:\n{open_targets_p445}\n")

    except ValueError as invalid_ip_block:
        print(f"\nError: Invalid address block\n{invalid_ip_block}")


    enumerate_shares(port_445=open_targets_p445)


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
