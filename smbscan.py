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

    smb_ports = [139, 445]
    open_targets_p139 = []
    open_targets_p445 = []

    try:
        # get the provided ip block and convert to ipaddress object
        address_block = (ipaddress.ip_network(str(network), strict=False).hosts())

        # create a generator containing each IP as string
        hosts = map(str, address_block)

        # total hosts
        total_hosts = ipaddress.ip_network(network).num_addresses
        print(f"Total scans to execute: {total_hosts}")

        
        # iterate the target network or host
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
                        open_targets_p139.append(ip)
                    else:
                        open_targets_p445.append(ip)
                    
                except socket.error as socket_error:
                    continue
                finally:
                    # close connection after each connection attempt
                    connection.close()

        print(f"Targets listening on port 139:\n{open_targets_p139}\n")
        print(f"Targets listening on port 445:\n{open_targets_p445}\n")

    except ValueError as invalid_ip_block:
        print(f"\nError: Invalid address block\n{invalid_ip_block}")


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
