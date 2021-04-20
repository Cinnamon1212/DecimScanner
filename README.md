# DecimScanner

## Overview  
A python package for threaded scanning

## Features  

### <ins>TCP Scans</ins>  
* TCP Connect  
* SYN/Stealth Scan  
* FIN Scan  
* NULL Scan  
* ACK Scan  
* XMAS Scan  
* Window Scan  
* Idle Scan  

### <ins>UDP Scans</ins>    
* UDP Connect

### <ins> ICMP Scans</ins>  
* ICMP Ping
* IP Protocol Scan

## To Do List   

* Add more UDP scans  
* Create ARP class with relevant scans  
* Create Wireless and Bluetooth scans  
* Ensure all errors are correctly handled with a custom message  
* Add service discovery to TCP Connect (or make a seperate scan)  
* Add OS detection (and make a seperate scan)  

## Set Up

### Requirements
* [Scapy](https://scapy.readthedocs.io/)  
```sh 
pip install scapy
```
* [Python3](https://www.python.org/)   
```sh 
apt install python3
```
* [Pybluez](https://github.com/pybluez/pybluez)  
```sh 
pip install pybluez
```

### Commands
PIP:
```sh
pip3 install DecimScanner
```
Manual:
```sh
git clone https://github.com/Cinnamon1212/DecimScanner.git
tar -xzf (tar file name)
python3 setup.py install
```

### Python example
**Format: DecimScanner.(ScanPlatform/Protocol).(ScanType)**

```py  
import DecimScanner  
RandomlyGeneratedIPs = ["91.141.119.216", "204.45.197.227", "76.145.131.209", "112.77.12.53" ,"25.98.239.105"]
ports = [21, 22, 80, 443]   
scan = DecimScanner.TCPScans.FINScan(RandomlyGeneratedIPs, ports, timeout=0.5, max_threads=50)  
```

## Creator contact   
Please contact me via [Github](https://github.com/Cinnamon1212/) or [Cinnamon#7617](https://discord.com/users/292382410530750466/) on discord for with concerns or queries

## Patreon  
Donations are always appreicated! [Patreon](https://www.patreon.com/cinnamon1212) 


## Other Repos
* [CyberSecurity Bot](https://github.com/Cinnamon1212/CyberSecDiscordBot)
* [LAN Pwning Toolkit](https://github.com/Cinnamon1212/LAN_Pwning_Toolkit)
* [BlueKit](https://github.com/Cinnamon1212/BlueKit)
