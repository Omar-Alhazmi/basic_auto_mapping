
import re
#192.168.56.102

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535

import nmap

def fullScan(scan_ip,port_range):
    Os_type = ''
    test = nm.scan(scan_ip, port_range,"-A", True)['scan'][scan_ip]['hostscript']
    for output in test:
        if output['id'] == "smb-os-discovery":
                OS_re = re.compile('(?<=OS:).*')
                OS = OS_re.search(output['output'])
                if OS:
                    OS=OS.group().strip()
                    Os_type = OS
    nm.scan(scan_ip, port_range)
    nm.command_line()
    f'nmap -oX - -p 22-443 -sV {scan_ip}'
    nm.scaninfo()
    {'tcp': {'services': '22-443', 'method': 'connect'}}
    nm.scaninfo()
    {'tcp': {'services': '22-443', 'method': 'connect'}}
    nm.all_hosts()
    [scan_ip]
    #nm[scan_ip].state()
    #'up'
    nm[scan_ip].all_protocols()
    ['tcp']
    nm[scan_ip]['tcp'].keys()
    [80, 25, 443, 22, 111]
    nm[scan_ip].has_tcp(22)
    True
    nm[scan_ip].has_tcp(23)
    False
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print("Nmap Version: ", nm.nmap_version())
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print(Os_type)
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
        lport = nm[host][proto].keys()
        print('------------------------------------------------------------------------------')
        print('|\tport \t |\tstate \t|\t\tproduct \t\t     |')
        print('------------------------------------------------------------------------------')
        for port in lport:
            print ('|\t%s \t |\t%s \t|\t%s \t  ' % (port, nm[host][proto][port]['state'],nm[host][proto][port]['product']))
            print('------------------------------------------------------------------------------')

def netWork_status(scan_ip):    
    splited_ip = scan_ip.split('.')
    splited_ip[3] = 0
    netWork_ip = '.'.join([str(element) for element in splited_ip])
    nm.scan(hosts=f'{netWork_ip}/24', arguments='-n -sP -PE -PA21,23,80,3389')
    print('====================')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print(f'{host} >>> {status}')

def syn_ack_scan(scan_ip,port_range):
    print("Nmap Version: ", nm.nmap_version())
    # Here, v is used for verbose, which means if selected it will give extra information
    # 1-1024 means 19the port number we want to search on
    #-sS means perform a TCP SYN connect scan, it send the SYN packets to the host
    nm.scan(scan_ip,port_range, '-v -sS',True)
    print(nm.scaninfo())
    # state() tells if target is up or down
    print("Ip Status: ", nm[scan_ip].state())
    # all_protocols() tells which protocols are enabled like TCP UDP etc
    print("protocols:",nm[scan_ip].all_protocols())
    print("Open Ports: ", nm[scan_ip]['tcp'].keys())

def udp_scan(scan_ip,port_range):
    # Here, v is used for verbose, which means if selected it will give #extra information
    # 1-1024 means the port number we want to search on
    #-sU means perform a UDP SYN connect scan, it send the SYN packets to #the host
    print("Nmap Version: ", nm.nmap_version())
    nm.scan(scan_ip,port_range, '-v -sU',True)
    print(nm.scaninfo())
    # state() tells if target is up or down
    print("Ip Status: ", nm[scan_ip].state())
    # all_protocols() tells which protocols are enabled like TCP UDP etc
    print("protocols:",nm[scan_ip].all_protocols())
    print("Open Ports: ", nm[scan_ip]['udp'].keys())

def main():
    print(r"""         
         \                          /    /|
          \                        /    / |
           ]                      [    /  |
           ]                      [   /   |   
           ]___                ___[  /    |
           ]  ]\             /[  [  /     |
           ]  ] \           / [  [ |      |
           ]  ]  ]         [  [  [ |      |
           ]  ]  ]__     __[  [  [ |     o| 
           ]  ]  ] ]     [ [  [  [ |      | 
           ]  ]  ] ]     [ [  [  [ |      |
           ]  ]  ]_]     [_[  [  [ |      |
           ]  ]  ]         [  [  [ |     / 
           ]  ] /           \ [  [ |    /  
           ]__]/             \[__[ |   /   
           ]                     [ |  /     
           ]                     [ | /     
           ]                     [ |/       
          /    ;;;                \   
         /    ;   ;  /\  /\   /\   \       
        /      ;;;  /  \/  \ /""\   \  
       /                             \
""")

print('=======================================')
print('|   Welcome To nmap Automation Scan   |')
print('=======================================')
nm = nmap.PortScanner()
scan_ip = input('Pleas Enter Ip to Scan:\n')
port_range = input('Pleas Enter The Port range ??-?? from 0 to 65535:\n')
while True:
    userInput = int(input("""\nPlease enter the type of scan you want to run
                1)Check the network status
                2)Comprehensive Scan
                3)SYN ACK Scan
                4)UDP Scan
                5)Change the IP
                6)Change the Port Range
                7)Quit
                \n"""))
    if userInput == 1:
        netWork_status(scan_ip)
    elif userInput == 2:
        fullScan(scan_ip,port_range)
    elif userInput == 3:
        syn_ack_scan(scan_ip,port_range)
    elif userInput == 4:
        udp_scan(scan_ip,port_range)
    elif userInput == 5:
        scan_ip = input('Pleas Enter Ip to Scan:\n')
    elif userInput == 6:
        port_range = input('Pleas Enter The Port range ??-?? from 0 to 65535:\n')
    elif userInput == 7:
        quit()
    else:
        print("Please choose a valid number from the list")
                     

main()

