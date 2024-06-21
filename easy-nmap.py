#!/usr/bin/python3

import nmap
import os
import time

clear_command = "clear"
sleeptime = 10

class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR

scanner = nmap.PortScanner()

def clear_screen():
    os.system(clear_command)

def get_ip_address():
    while True:
        ip_addr = input("Please enter the IP address you want to scan: ").strip()
        if ip_addr:
            return ip_addr
        else:
            print(f"{bcolors.FAIL}Invalid input! Please enter a valid IP address.{bcolors.RESET}")

def get_port_range():
    while True:
        port_range = input("Please enter the port range you want to scan (e.g., 1-1024): ").strip()
        if port_range:
            return port_range
        else:
            print(f"{bcolors.FAIL}Invalid input! Please enter a valid port range.{bcolors.RESET}")

def get_scan_type():
    scan_types = {
        '1': 'SYN ACK Scan',
        '2': 'UDP Scan',
        '3': 'Comprehensive Scan',
        '4': 'Ping Scan',
        '5': 'TCP Connect Scan',
        '6': 'FIN Scan',
        '7': 'Stealth Scan',
        '8': 'IP Protocol Scan'
    }
    
    for key, value in scan_types.items():
        print(f"{key}) {value}")
    
    while True:
        resp = input("\nPlease enter the type of scan you want to run: ").strip()
        if resp in scan_types:
            return resp
        else:
            print(f"{bcolors.FAIL}Invalid option! Please select a valid scan type.{bcolors.RESET}")

def save_results(ip_addr, scan_type, results):
    file_name = f"scan_results_{ip_addr.replace('.', '_')}_{scan_type}.txt"
    with open(file_name, 'w') as f:
        f.write(results)
    print(f"{bcolors.OK}Results saved to {file_name}{bcolors.RESET}")

def run_scan(ip_addr, port_range, scan_type):
    scan_options = {
        '1': '-v -sS',
        '2': '-v -sU',
        '3': '-v -sS -sV -sC -A -O',
        '4': '-v -sn',
        '5': '-v -sT',
        '6': '-v -sF',
        '7': '-v -sN',
        '8': '-v -sO'
    }
    
    try:
        print(f"Nmap Version: {scanner.nmap_version()}")
        scanner.scan(ip_addr, port_range, scan_options[scan_type])
        scan_info = f"{scanner.scaninfo()}\nIP Status: {scanner[ip_addr].state()}\n"
        protocols = scanner[ip_addr].all_protocols()
        scan_info += f"Protocols: {protocols}\n"
        
        for protocol in protocols:
            scan_info += f"Open Ports ({protocol}): {list(scanner[ip_addr][protocol].keys())}\n"
        
        print(scan_info)
        
        save_option = input("Do you want to save the results to a file? (yes/no): ").strip().lower()
        if save_option == 'yes':
            save_results(ip_addr, scan_type, scan_info)
    except Exception as e:
        print(f"{bcolors.FAIL}An error occurred while scanning: {e}{bcolors.RESET}")

def main():
    while True:
        clear_screen()
        
        print(f"{bcolors.WARNING}Welcome, this is a simple nmap automation tool\n<----------------------------------------------------->{bcolors.RESET}")
        
        ip_addr = get_ip_address()
        print(f"The IP you entered is: {ip_addr}")
        
        port_range = get_port_range()
        print(f"The Port Range you entered is: {port_range}")
        
        scan_type = get_scan_type()
        print(f"{bcolors.OK}You have selected option: {scan_type}{bcolors.RESET}")
        
        run_scan(ip_addr, port_range, scan_type)
        
        repeat = input("Do you want to run another scan? (yes/no): ").strip().lower()
        if repeat != 'yes':
            print(f"{bcolors.OK}Exiting the program. Goodbye!{bcolors.RESET}")
            break

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"{bcolors.FAIL}An error has occurred: {e}{bcolors.RESET}")
