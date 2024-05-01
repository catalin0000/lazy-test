#!/usr/bin/python3
# i am lazy, let the script do it for me.
import os
import argparse
import subprocess
from multiprocessing import Pool
import glob
import json
import sys,sqlite3 as lite,os,argparse,ast


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
    parser.add_argument("-o", "--output", help="directory for output", default="./")
    args = parser.parse_args()

#Magic Variables
dbfile="lazy-test.db"
svcarrayfile="services.array"
svcfolder="services"

nmap_res={}

def db_connect():
    con = lite.connect(db)
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name;")
    tables = cur.fetchall()
    if not tables:
        #try:
        cur.execute("CREATE TABLE scope (ip varchar(16), network varchar(19), live integer(1) default 0, excluded integer(1) default 0, arpscan integer(1) default 0, discoveryscan integer(1) default 0, top20scan integer(1) default 0, nmapprocessed integer(1) default 0, fulltcpscan integer(1) default 0, fulludpscan integer(1) default 0);")
        cur.execute("CREATE TABLE openports (ip varchar(16), port integer(5), protocol varchar(3), service varchar(100), tunnel varchar(4), version varchar(100));")
        cur.execute("CREATE TABLE closedports (ip varchar(16), port integer(5), range varchar(100), protocol varchar(3));")
        cur.execute("CREATE TABLE hostnames (hostname varchar(500), ip varchar(16));")
        cur.execute("CREATE TABLE osmatch (name varchar(100), accuracy int(3), ip varchar(16));")
        cur.execute("CREATE TABLE scripts (id varchar(100), ip varchar(16), port integer(5), output varchar(512));")
        cur.execute("CREATE UNIQUE INDEX scopedip ON scope (ip);")
        cur.execute("CREATE UNIQUE INDEX opencheck ON openports (ip,port,protocol);")
        cur.execute("CREATE UNIQUE INDEX closedcheckip ON closedports (ip,port,protocol);")
        cur.execute("CREATE UNIQUE INDEX closedcheckrange ON closedports (ip,range,protocol);")
        cur.execute("CREATE UNIQUE INDEX scriptcheck ON scripts (id,ip,port);")
        cur.execute("CREATE UNIQUE INDEX hostnamecheck ON hostnames (hostname,ip);")
        cur.execute("CREATE UNIQUE INDEX osmatchcheck ON osmatch (name,accuracy,ip);")
        #except Exception as e:
        #    print(e)
    return con

def nmap_scan(ip):
    if "/" in str(ip): 
        print('if you are looking to test an internal network this is not the way, use naptest')
        targets = ip.split('/')[0]
        # subprocess.run(['nmap','-sn','-oA',f'nmap/{targets}.hosts.up',ip])
    else:
        print('lets say scan is done')
        # subprocess.run(['nmap','-Pn','--min-rate=500','--max-retries=3','--max-rtt-timeout=900ms', '-T4', '-sS','-dd','-oA',f'nmap/{ip}.tcp',ip])

def filehandler(arginput):
    if os.path.isfile(arginput):
        xmlimport(arginput)
    elif os.path.isdir(arginput):
        for xmlfile in os.listdir(arginput):
            if xmlfile.endswith('.xml'):
                xmlimport(os.path.join(arginput, xmlfile))
# Finds any port with SSL listening and adds them to the service array     
def findssl():
    print("[+] SSL port identification")
    con=lite.connect(db)
    con.row_factory = lite.Row
    cur = con.cursor()
    cur.execute('select ip,port from openports where tunnel="ssl" and protocol="tcp";')
    ssldb = cur.fetchall()
    if ssldb:
        nowlist=[]
        for row in ssldb:
            ip = row['ip']
            port = str(row['port'])
            nowlist.append(ip+":"+port)
            hnlist = gethostnames(ip)
            for hn in list(hnlist):
                nowlist.append(hn+":"+port)
        servicearray['sslport']={"tcp": nowlist}
        print("   [*] Found "+str(len(nowlist))+" SSL ports")

# Identifies HTTP and HTTPS and put them into the service array
def findhttp(SSL):
    con=lite.connect(db)
    con.row_factory = lite.Row
    cur = con.cursor()
    if SSL == '1':
        print("[+] HTTPS identification")
        tunnel='ssl'
        service='securehttp'
    else:
        print("[+] HTTP identification")
        tunnel='none'
        service='plainhttp'
    cur.execute('SELECT ip,port FROM openports WHERE service like "%http%" and tunnel="'+tunnel+'" and protocol="tcp";')
    httpdb=cur.fetchall()
    nowlist=[]
    if httpdb:
        for row in httpdb:
            ip = row['ip']
            port = str(row['port'])
            nowlist.append(ip+":"+port)
            hnlist = gethostnames(ip)
            for hn in list(hnlist):
                nowlist.append(hn+":"+port)
        servicearray[service]={"tcp": nowlist}
        print("   [*] Found "+str(len(nowlist))+" "+service+" ports")

# Gets hostnames from an IP
def gethostnames(ip):
    con=lite.connect(db)
    con.row_factory = lite.Row
    cur = con.cursor()
    hostnamelist = []
    try:
        response = cur.execute("select hostname from hostnames where ip='"+ip+"';").fetchall()
        for row in response:
            hostnamelist.append(row['hostname'])
    except:
        pass
    return(hostnamelist)

# Finds any closed ports and adds them to the service array
def findclosed():
    print("[+] Closed port identification")
    con=lite.connect(db)
    con.row_factory = lite.Row
    cur = con.cursor()
    cur.execute('select ip,protocol,range from closedports where port is null;')
    closeddb = cur.fetchall()
    if closeddb:
        nowlist=[]
        for row in closeddb:
            cip = row['ip']
            crange = row['range']
            cprotocol = row['protocol'].upper()
            string = cip+";"+cprotocol+";"+str(crange)+";"
            nowlist.append(string)
        servicearray['closed ranges']={"": nowlist}
        print("   [*] Found "+str(len(nowlist))+" closed ranges")
    cur.execute('select ip,protocol,port from closedports where range is null;')
    closeddb = cur.fetchall()
    if closeddb:
        nowlist=[]
        for row in closeddb:
            cip = row['ip']
            cport = row['port']
            cprotocol = row['protocol'].upper()
            string = cip+";"+cprotocol+";"+str(cport)+";"
            nowlist.append(string)
        servicearray['closed ports']={"": nowlist}
        print("   [*] Found "+str(len(nowlist))+" closed ports")

def findservices():
    global servicearray
    print("[+] Enumerating services")
    con=lite.connect(db)
    cur = con.cursor()
    cur.execute('SELECT distinct service,protocol FROM openports;')
    servicelist = cur.fetchall()
    for service,protocol in servicelist:
        cur.execute('SELECT ip ||":"|| port FROM openports WHERE service="'+service+'"and protocol="'+protocol+'";')
        hostports=cur.fetchall()
        nowlist=[]
        if service not in servicearray:
            servicearray[service]={}
        for line in hostports:
            nowlist.extend(line)
        servicearray[service][protocol]=nowlist
    print("   [*] Found "+str(len(servicelist))+" distinct services")
    findssl()
    findhttp(0)
    findhttp("1")
    findclosed()

# Writes the services out as an array to file
def outputarray():
    obfile = open (os.path.join(args.output,'parsed.dir',svcarrayfile), 'w')
    obfile.write(str(servicearray))
    obfile.close

# Writes the output to files            
def outputfiles():
    location = args.output
    servicedir = os.path.join(location, 'parsed.dir', svcfolder)
    try:
        os.mkdir(servicedir)
    except OSError:
        print("[!] Output folder already exists- overwriting")
        pass
    for service in servicearray:
        for protocol,hostports in servicearray[service].items():
            if len(hostports) > 0:
                protocoldir = os.path.join(servicedir,protocol)
                try: os.mkdir(protocoldir)
                except: pass
                filename=service.replace('/','_')+'.service'
                prefix=""
                if service=="sslport":
                    filename="ssl.host"
                elif service=="securehttp":
                    filename="webapp.url.https"
                    prefix="https://"
                elif service=="plainhttp":
                    filename="webapp.url.http"
                    prefix="http://"
            
                sfile = open (os.path.join(protocoldir, filename), 'w')
                for line in hostports:
                    sfile.write(prefix+str(line)+"\n")
                sfile.close

    # Makes a directory for informational output
    infodir = os.path.join(location, 'parsed.dir',"info")
    try:
        os.mkdir(infodir)
    except:
        pass

    # Write the ports for nessus/nmap to file
    con=lite.connect(db)
    con.row_factory = lite.Row
    cur = con.cursor()
    port_list = cur.execute('SELECT distinct port,protocol from openports;').fetchall()
    if port_list:
        tcplist=[]
        udplist=[]
        for row in port_list:
            port = str(row['port'])
            protocol = row['protocol']
            if protocol == "tcp":
                tcplist.append(port)
            elif protocol == "udp":
                udplist.append(port)
                
        openfile = open (os.path.join(infodir,"nessus.ports"), 'w')
        if tcplist:
            openfile.write("T:"+",".join(tcplist))
        if tcplist and udplist:
            openfile.write(",")
        if udplist:
            openfile.write("U:"+",".join(udplist))
        openfile.close()
    
    # Writes live IPs to file
    con=lite.connect(db)
    con.row_factory = None
    con.text_factory = str
    cur = con.cursor()
    ip_list = cur.execute('select distinct ip from openports union select distinct ip from closedports;').fetchall()
    openfile = open (os.path.join(infodir,"live.ips"), 'w')
    for ip in ip_list:
        openfile.write(''.join(ip)+"\n")
    openfile.close()

    # Writes plaintext protocols
    nonplaintextservices = ['ssh','isakmp','ms-wbt-server']
    con=lite.connect(db)
    con.row_factory = None
    con.text_factory = str
    cur = con.cursor()
    ip_list = cur.execute('select ip,protocol,port,service from openports where tunnel=\'none\' and service != \'tcpwrapped\';').fetchall()
    openfile = open (os.path.join(infodir,"plaintext.ports"), 'w')
    for line in ip_list:
        ip = line[0]
        proto = line[1]
        port = str(line[2])
        service = str(line[3])
        if service not in nonplaintextservices:
            openfile.write(ip+";"+proto+";"+port+";:"+service+"\n")
    openfile.close()

    # Write OS matches and identified software versions to file
    con=lite.connect(db)
    con.row_factory = lite.Row
    cur = con.cursor()
    ip_list = cur.execute('SELECT distinct ip from openports;').fetchall()
    for row in ip_list:
        ip = row['ip']
        osmatches = cur.execute('SELECT name,accuracy FROM osmatch where ip="'+str(ip)+'";').fetchall()
        port_list = cur.execute('SELECT port,protocol,version from openports where version!=NULL and ip="'+str(ip)+'";').fetchall()
        if osmatches or port_list:
            openfile = open (os.path.join(infodir,ip+".info"), 'w')
        if osmatches:
            openfile.write("OS Matches\n")
            for name,accuracy in osmatches:
                openfile.write(str(accuracy)+"%  : "+name+"\n")
            openfile.write("\n\n")
        if port_list:
            openfile.write("Detected Software Versions\n")
            for port,protocol,version in port_list:
                if version != " ":
                    openfile.write(str(port)+"/"+protocol+"   "+version+"\n")
                    
    # Writes script output to files
    con=lite.connect(db)
    con.row_factory = lite.Row
    cur = con.cursor()
    ip_list = cur.execute('SELECT distinct ip from scripts;').fetchall()
    if ip_list:
        scriptdir = os.path.join(location, "scripts")
        try:
            os.mkdir(scriptdir)
        except:
            pass
        for row in ip_list:
            ip = row['ip']
            script_list = cur.execute('SELECT id,port,output from scripts where ip="'+ip+'";').fetchall()
            ipdir = os.path.join(scriptdir, str(ip))
            os.mkdir(ipdir)
            for id,port,output in script_list:
                openfile = open (os.path.join(ipdir,str(id)), 'w')
                openfile.write(ip+":"+str(port)+"\n\n")
                openfile.write(str(output)+"\n")
                openfile.close

def closedports_to_ports_list(closedports):
    clist = []
    qlist = closedports.split(",")
    for i in qlist:
        iint = False
        try:
            int(i)
            iint = True
        except:
            pass
        if iint is True:
            clist.append(i)
        else:
            start=int(i.split("-")[0])
            end=int(i.split("-")[1])
            for i in range(start,end+1):
                clist.append(i)
    return clist


def xmlimport(xmlfile):
    import xml.etree.ElementTree as ET
    con = db_connect()
    cur = con.cursor()
    cur.row_factory = lambda cursor, row: row[0]

    try:
        tree = ET.ElementTree(file = xmlfile)
        root = tree.getroot()
    except:
        print("[!] Error parsing XML from: "+xmlfile)
        return


    # Loop through and pull out the data for the db

    # Get IP Address and hostnames
    for host in root.iterfind('host'):
        ip = host.find("./address").attrib['addr']
        hostname = []
        try:
            for name in host.find("./hostnames"):
                hostname.append(name.attrib['name'])
        except:
            pass
        osmatch =[]
        try:
            for match in host.findall("./os/osmatch"):
                name = match.attrib['name']
                accuracy = match.attrib['accuracy']
                osmatch.append((name,accuracy))
        except:
            pass
        cur.execute("UPDATE scope set nmapprocessed = 1 where ip = ?",(ip,))
    
        # Identifies batches of closed ports    
        for extraport in host.findall("./ports/extraports"):
            if extraport.attrib['state'] == "closed":
                closed_protocol=extraport.find("./extrareasons").attrib['proto']
                closed_ports=extraport.find("./extrareasons").attrib['ports']
                closedport_list = closedports_to_ports_list(closed_ports)
                if closed_protocol != "udp":
                    for port in closedport_list:
                        try:
                            cur.execute("INSERT INTO closedports (ip,protocol,port) values (?,?,?)",(ip,closed_protocol,port)) 
                        except Exception as e:
                            pass
                    for crange in closed_ports.split(","):
                        try:
                            cur.execute("INSERT INTO closedports (ip,protocol,range) values (?,?,?)",(ip,closed_protocol,crange)) 
                        except Exception as e:
                            pass
        
        # Hostnames into database
        if hostname:
            for name in hostname:
                try:
                    cur.execute("INSERT INTO hostnames (hostname,ip) VALUES (?,?)",(str(name),ip))
                except:
                    pass
        
        # OS Match into database
        if osmatch:
            for name,accuracy in osmatch:
                try:
                    cur.execute("INSERT INTO osmatch (name,accuracy,ip) VALUES (?,?,?)",(str(name),str(accuracy),ip))
                except Exception as e:
                    pass

        # Work through each port in the nmap output
        for openport in host.iter('port'):
            port = openport.attrib['portid']
            protocol = openport.attrib['protocol']
            state = openport.find("./state").attrib['state']
            try: service = openport.find("./service").attrib['name']
            except: service = "empty"
            try: tunnel = openport.find("./service").attrib['tunnel']
            except: tunnel="none"
            try: product = openport.find("./service").attrib['product'] 
            except: product=""
            try: productversion = openport.find("./service").attrib['version']
            except: productversion=""

            # Scripts
            for script in openport.findall('script'):
                sid = script.attrib['id']
                soutput = script.attrib['output']
                try:
                    cur.execute("INSERT INTO scripts (id,ip,port,output) VALUES (?,?,?,?)",(sid,ip,port,soutput))
                except Exception as e:
                    pass

             #enter into db
            if state == "open":
                dbtable = "openports"
                try:
                    cur.execute("INSERT INTO "+dbtable+" (ip,port,protocol,service,tunnel,version) values (?,?,?,?,?,?)",(ip,port,protocol,service,tunnel,product+' '+productversion)) 
                except:
                    pass
            elif state == "closed":
                dbtable = "closedports"
                try:
                    cur.execute("INSERT INTO "+dbtable+" (ip,port,protocol) values (?,?,?)",(ip,port,protocol)) 
                except:
                    pass
            if state in ["open","closed"]:
                try:
                    cur.execute("UPDATE scope set live = 1 where ip = ?",(ip,))
                except Exception as e:
                    print(e)
        
    con.commit()
    con.close()


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



def runtests():
    if not os.path.exists('tests'):
        os.mkdir('tests')
    
    if not os.path.exists(os.path.join(os.getcwd(), 'tests', 'ssl')):
        os.mkdir('tests/ssl')
        

    for key in servicearray.keys():
        if key == 'closed ranges' or key == 'closed ports':
            continue
        else:
            print(key)
            if key == 'ftp':
                print('running ftp scan on:',servicearray[key])
            if key == 'http' or key == 'https':
                print(servicearray[key], 'will run dirb')
            if key == 'sslport':
                with Pool(processes=20) as pool:
                        pool.map(testssl, servicearray[key]['tcp'])
            

def testssl(ip):
    subprocess.run(['testssl', '-oJ', f'tests/ssl/{ip}.json',ip])

def dirb(host):
    subprocess.run(['testssl', '-oJ', f'tests/ssl/{ip}.json',ip])

if __name__ == '__main__':
    global servicearray
    servicearray = {}
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

        current_directory = os.getcwd()

        if not os.path.exists('parsed.dir'):
            os.mkdir('parsed.dir')
        db = os.path.join(current_directory,'parsed.dir', dbfile)
        filehandler(os.path.join(current_directory, 'nmap'))
        findservices()
        outputarray()
        outputfiles()
        runtests()
        # print(servicearray)

    if args.parse:
        db = os.path.join(args.output, dbfile)
        filehandler(args.parse)
        findservices()
        outputarray()
        outputfiles()

    # if args.parse:
    #     file_path = args.parse
    #     if os.path.isfile(file_path):
    #         try:
    #             nmap_results = ET.ElementTree(file=f)
    #             parse_ips(nmap_results)
    #             if args.test:
    #                 None
    #             else:
    #                 with open('nmap_open_ports.json', 'w') as f:
    #                     json.dump(nmap_res, f)

    #         except:
    #             print("That's not a recognised file type.")

    #     elif os.path.isdir(file_path):
    #         files = glob.glob(f"{file_path}/*.xml")
    #         if args.test:
    #             for f in files:

    #                 try:
    #                     nmap_results = ET.ElementTree(file=f)
    #                     parse_ips(nmap_results)   


    #                 except Exception as e:
    #                     print(f"Error parsing {f}: {e}")
            
    #             try:
    #                 None
    #             except:
    #                 None

    #         else:
    #             for f in files:  
    #                 try:
    #                     nmap_results = ET.ElementTree(file=f)
    #                     parse_ips(nmap_results)   

                                         
    #                 except Exception as e:
    #                     print(f"Error parsing {f}: {e}")


    #             with open('nmap_open_ports.json', 'w') as f:
    #                         json.dump(nmap_res, f)

                

    # print(nmap_res)





