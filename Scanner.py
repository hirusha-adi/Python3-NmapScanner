#!/usr/bin/python3

import nmap
import os
import time

clear = "clear"
sleeptime = 10

class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR


scanner = nmap.PortScanner()

def ENTIRE_PROGRAM():
    os.system(clear)

    print(f"{bcolors.WARNING}    Welcome, this is a simple nmap automation tool\n<----------------------------------------------------->{bcolors.RESET}")

    ip_addr = input("Please enter the IP address you want to scan: ")
    print("The IP you entered is: ", ip_addr)
    type(ip_addr)

    resp = input("""1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n\nPlease enter the type of scan you want to run: """)
    print(f"{bcolors.OK}You have selected option: {resp} {bcolors.RESET}")

    if resp == '1':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sS')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

    elif resp == '2':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sU')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['udp'].keys())

    elif resp == '3':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

    else:
        print(f'{bcolors.FAIL}{resp} is not a recognized command! Please try again!{bcolors.RESET}')
        time.sleep(sleeptime)
        ENTIRE_PROGRAM()


if __name__ == '__main__':
    try:
        ENTIRE_PROGRAM()
    except Exception as e:
        print(f'{bcolors.FAIL}An Error has occured: {e}{bcolors.RESET}')
