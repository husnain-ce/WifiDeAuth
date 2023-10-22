import os
import subprocess
import json
import csv
import time
import signal
from termcolor import colored

# Load trusted devices from JSON file
with open("trusted_devices.json", "r") as f:
    TRUSTED_DEVICES = json.load(f)


# Enable monitor mode using airmon-ng
def enable_monitor_mode(interface):
    process = subprocess.Popen(["sudo", "airmon-ng", "start", interface], stdout=subprocess.PIPE)
    output, error = process.communicate()

    # Extract the new interface name from the output
    new_interface = None
    for line in output.decode().split("\n"):
        if line.startswith("mon"):
            new_interface = line.split()[1]
            break

    # Bring the new interface up
    if new_interface is not None:
        process = subprocess.Popen(["sudo", "ifconfig", new_interface, "up"], stdout=subprocess.PIPE)
        output, error = process.communicate()

    return new_interface

# Disable monitor mode
def disable_monitor_mode(interface):
    print('working')
    process = subprocess.Popen(["sudo", "airmon-ng", "stop", interface], stdout=subprocess.PIPE)
    output, error = process.communicate()

    # Extract the original interface name from the output
    original_interface = None
    for line in output.decode().split("\n"):
        if line.startswith("Interface"):
            original_interface = line.split()[1]
            break

    # Bring the original interface up
    if original_interface is not None:
        process = subprocess.Popen(["sudo", "ifconfig", original_interface, "up"], stdout=subprocess.PIPE)
        output, error = process.communicate()

    return original_interface


def detect_rogue_hotspots():
    # Use airodump-ng to scan for all nearby Wi-Fi networks and save the output to a file
    print(colored("Starting airodump-ng...", "cyan"))

    # cmd = "sudo airodump-ng wlan0mon -w scan --output-format csv"
    # process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # try:
    #     process.wait(timeout=10)
    # except subprocess.TimeoutExpired:
    #     process.terminate()
    # output, error = process.communicate()

    print(colored("Finished airodump-ng.", "cyan"))

    # Wait for 10 seconds to allow airodump-ng to capture enough data
    print(colored("Waiting for airodump-ng to capture data...", "cyan"))
    # time.sleep(10)
    bssid_list = []
    essid_list = []

    with open('scan-01.csv') as csv_file:
        csv_reader = csv.reader(csv_file)
        
        # Skip the header row
        next(csv_reader)
        
        # Loop over the rows and print each field
        try:
            for row in csv_reader:
                bssid = row[0]
                bssid_list.append(row[0])
                first_seen = row[1]
                last_seen = row[2]
                channel = row[3]
                speed = row[4]
                privacy = row[5]
                cipher = row[6]
                authentication = row[7]
                power = row[8]
                num_beacons = row[9]
                num_iv = row[10]
                lan_ip = row[11]
                id_length = row[12]
                essid = row[13]
                essid_list.append(row[13])
                key = row[14]
            
            
                print(colored(f"BSSID: {bssid}  First Seen: {first_seen}  Last Seen: {last_seen}  Channel: {channel}  Speed: {speed}  Privacy: {privacy}  Cipher: {cipher}  Authentication: {authentication}  Power: {power}  Beacons: {num_beacons}  IV: {num_iv}  LAN IP: {lan_ip}  ID Length: {id_length}  ESSID: {essid}  Key: {key}", "green"))
            
        except: pass

    # Look for any Wi-Fi networks that don't have a recognized MAC address
    found_rogue = False
    # try:
    print(bssid_list, essid_list)
    bssid_list.remove('BSSID')
    essid_list.remove(' ESSID')
    
    with open('info.txt', mode='w') as f1:
        for bssid, essid in zip(bssid_list, essid_list):
            f1.write(f'{bssid} {essid}')
            f1.write('\n')

    for device, bssid_device, essid in zip(TRUSTED_DEVICES, bssid_list, essid_list):
        if device['BSSID'] == bssid_device:
            print(colored(f"Rogue hotspot detected with MAC address: {device['BSSID']}: {device['SSID']} {essid_list[essid]}", "red"))
            found_rogue = True

    # except: pass

    if not found_rogue:
        print(colored("No rogue hotspots detected.", "green"))


def list_devices():
    # Use airmon-ng to list all Wi-Fi devices
    process = subprocess.Popen(["sudo", "airmon-ng"], stdout=subprocess.PIPE)
    output, error = process.communicate()

    # Extract the MAC addresses of each device
    devices = []
    with open('bssid_List.txt', mode='r') as txt_file:
        devices = txt_file.read().splitlines()
       
    with open('bssid_List.txt', mode='r') as txt_file:
        devices = txt_file.read().splitlines()
                
    if len(devices) == 0:
        print(colored("No other Wi-Fi devices detected.", "green"))
    else:
        # Print the list of trusted devices
        print(colored("Trusted Wi-Fi devices:", "cyan"))
        for device in TRUSTED_DEVICES:
            print(colored(device["BSSID"], "green"))
        
        # Print the list of detected devices and indicate whether they are trusted or not
        print(colored("\nDetected Wi-Fi devices:", "cyan"))
        for device in devices:
            found = False
            for trusted_device in TRUSTED_DEVICES:
                if device in trusted_device["BSSID"]:
                    print(colored(f"{device} (Trusted)", "green"))
                    found = True
                    break
           
            if not found:
                print(colored(f"{device} (Untrusted)", "red"))


def deauthenticate_rogue_hotspot(mac_address):
    # Use aireplay-ng to deauthenticate a rogue Wi-Fi network
    os.system(f"sudo aireplay-ng --deauth 100 -a {mac_address} wlan0mon")
    print(colored(f"Deauthentication attack completed against MAC address {mac_address}"), "red")

# Main function


def display_header():
    print(colored("""
__________                                      ___ ___         __                         __    ________          __                 __  .__               
\______   \ ____  __ __  ____  __ __   ____    /   |   \  _____/  |_  ____________   _____/  |_  \______ \   _____/  |_  ____   _____/  |_|__| ____   ____  
 |       _//  _ \|  |  \/ ___\|  |  \_/ __ \  /    ~    \/  _ \   __\/  ___/\____ \ /  _ \   __\  |    |  \_/ __ \   __\/ __ \_/ ___\   __\  |/  _ \ /    \ 
 |    |   (  <_> )  |  / /_/  >  |  /\  ___/  \    Y    (  <_> )  |  \___ \ |  |_> >  <_> )  |    |    `   \  ___/|  | \  ___/\  \___|  | |  (  <_> )   |  
 |____|_  /\____/|____/\___  /|____/  \___  >  \___|_  / \____/|__| /____  >|   __/ \____/|__|   /_______  /\___  >__|  \___  >\___  >__| |__|\____/|___|  /
        \/            /_____/             \/         \/                  \/ |__|                         \/     \/          \/     \/                    \/ """, "green"))
    print(colored("Rougue Hotspot Detection", "green", attrs=["bold", "underline"]))
    print(colored("Version 1.0\n", "green"))

def display_menu():
    print(colored("Select an option:", "blue"))
    print(colored("1. Detect rogue hotspots", "blue"))
    print(colored("2. List Wi-Fi devices", "blue"))
    print(colored("3. Deauthenticate a rogue hotspot", "blue"))
    print(colored("4. Exit", "blue"))

if __name__ == "__main__":
    monitor_mode = False # Flag variable for monitor mode
    display_header()

    while True:
        display_menu()
        choice = input(colored("Enter your choice: ", "yellow"))
        if choice == "1":
            if not monitor_mode: # If monitor mode is not enabled
                enable_monitor_mode("wlan0") # Enable monitor mode
                monitor_mode = True # Set flag variable to True
            detect_rogue_hotspots()
        elif choice == "2":
            if not monitor_mode: # If monitor mode is not enabled
                enable_monitor_mode("wlan0") # Enable monitor mode
                monitor_mode = True # Set flag variable to True
            list_devices()
        elif choice == "3":
            if not monitor_mode: # If monitor mode is not enabled
                enable_monitor_mode("wlan0") # Enable monitor mode
                monitor_mode = True # Set flag variable to True
            mac_address = input(colored("Enter the MAC address of the rogue hotspot: ", "yellow"))
            deauthenticate_rogue_hotspot(mac_address)
        elif choice == "4":
            print(colored(f"Monitor mode enabled: {monitor_mode}", "cyan"))
            if monitor_mode: # If monitor mode is enabled
                disable_monitor_mode("wlan0mon") # Disable monitor mode
                monitor_mode = False # Set flag variable to False
            print(colored("Exiting...", "green", attrs=["bold"]))
            break
        else:
            print(colored("Invalid choice. Please try again.", "red"))
