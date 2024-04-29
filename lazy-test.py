#!/usr/bin/python3
# i am lazy, let the script do it for me.
import os
import argparse
import subprocess
from multiprocessing import Pool
import glob
import json
import sys,sqlite3 as lite,os,ast


try:
    import  xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Usage: python3 lazy-test.py <path to file containing IPs or URLs>')
    parser.add_argument('-nmap', default='', help='input file/directory to run an nmap scan on it')
    parser.add_argument('-parse', default=False, help='parse the nmap output and creates open ports directory')
    parser.add_argument('-test', default=False, help='Create config items.', action=argparse.BooleanOptionalAction)
    parser.add_argument('-targethost', default=False, help='Use hostname as config items.', action=argparse.BooleanOptionalAction)
    parser.add_argument('-cloud', default=False, help='Sets the CVSS score for cloud internal network', action=argparse.BooleanOptionalAction)
    parser.add_argument('-internal', default=False, help='Sets the CVSS score for internal network', action=argparse.BooleanOptionalAction)
    args = parser.parse_args()


nmap_res={}


def nmap_scan(ip):
    if "/" in str(ip): 
        print('if you are looking to test an internal network this is not the way, use naptest')
        targets = ip.split('/')[0]
        subprocess.run(['nmap','-sn','-oA',f'nmap/{targets}.hosts.up',ip])
    else:
        subprocess.run(['nmap','-Pn','-p-','--min-rate=500','--max-retries=3','--max-rtt-timeout=900ms', '-T4', '-sS','-dd','-oA',f'nmap/{ip}.tcp',ip])

def file_read(file_path):
    if os.path.isfile(file_path):
            try:
                nmap_results = ET.ElementTree(file=f)
                parse_ips(nmap_results)
                if args.test:
                    None
                else:
                    with open('nmap_open_ports.json', 'w') as f:
                        json.dump(nmap_res, f)

            except:
                print("That's not a recognised file type.")


def parse_ips(file_path):
    if os.path.isfile(file_path):
            try:
                nmap_results = ET.ElementTree(file=f)
            except:
                print("That's not a recognised file type.")
    

    elif os.path.isdir(file_path):
        files = glob.glob(f"{file_path}/*.xml")
        for f in files:  
                    try:
                        nmap_results = ET.ElementTree(file=f)
                        parse_ips(nmap_results)   

                                         
                    except Exception as e:
                        print(f"Error parsing {f}: {e}")



    # Parse the xml for all IPv4 addresses which are good keys for each set of results
    host_ip = None
    open_ports = {}
    
    for host in nmap_results.findall('host'):
        for hostip in host.iterfind('address[@addrtype="ipv4"]'):
            host_ip = hostip.get('addr')


    for port in nmap_results.iter('port'):
        for portstate in port.iterfind('state[@state="open"]'):
            service = port.find('service')
            if service is None:
                open_ports[port.get('portid')] = [port.get('protocol'),'No known Service']
            else:
                open_ports[port.get('portid')] = [port.get('protocol'),service.get('name')]
    
    if open_ports:
        nmap_res[host_ip] = open_ports






if __name__ == '__main__':
    
    if args.nmap:
        os.makedirs('nmap', exist_ok=True)
        file_path = args.nmap
        if os.path.isfile(file_path):
            try:
                with open(file_path) as file:
                    targets_list=[line.strip() for line in file]
                    with Pool(processes=20) as pool:
                        pool.map(nmap_scan, targets_list)

            except FileNotFoundError:
                print("File not found.")

    if args.parse:
        file_path = args.parse
        if os.path.isfile(file_path):
            try:
                nmap_results = ET.ElementTree(file=f)
                parse_ips(nmap_results)
                if args.test:
                    None
                else:
                    with open('nmap_open_ports.json', 'w') as f:
                        json.dump(nmap_res, f)

            except:
                print("That's not a recognised file type.")

        elif os.path.isdir(file_path):
            files = glob.glob(f"{file_path}/*.xml")
            if args.test:
                for f in files:

                    try:
                        nmap_results = ET.ElementTree(file=f)
                        parse_ips(nmap_results)   


                    except Exception as e:
                        print(f"Error parsing {f}: {e}")
            
                try:
                    None
                except:
                    None

            else:
                for f in files:  
                    try:
                        nmap_results = ET.ElementTree(file=f)
                        parse_ips(nmap_results)   

                                         
                    except Exception as e:
                        print(f"Error parsing {f}: {e}")


                with open('nmap_open_ports.json', 'w') as f:
                            json.dump(nmap_res, f)

                

    print(nmap_res)





