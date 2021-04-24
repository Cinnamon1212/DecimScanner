# DecimScanner

## Overview  
A python package for threaded scanning

## Features  

### TCP Scans
* TCP Connect  
* Service Scan
* SYN/Stealth Scan  
* FIN Scan  
* NULL Scan  
* ACK Scan  
* XMAS Scan  
* Window Scan  
* Idle Scan  

### UDP Scans  
* UDP Connect

### ICMP Scans
* ICMP Ping
* IP Protocol Scan

### Traceroute
* DNS Traceroute
* UDP Traceroute
* TCP SYN Traceroute

### Web Scans
* Status Check
* Directory Check
* Web Crawler


### DNS
* DNS IPv4 enum
* DNS SOA
* DNS MX

### Bluetooth
* Get nearby (not threaded)
* Service scan

## To Do List   

* Add more UDP scans  
* Create ARP class with relevant scans  
* Create Wireless
* Ensure all errors are correctly handled with a custom message   
* Add OS detection (and make a separate scan)  

## Set Up

### Requirements
* [Python3](https://www.python.org/)   
```sh
apt install python3
```
* [Scapy](https://scapy.readthedocs.io/)  
```sh
pip install scapy
```
* [Pybluez](https://github.com/pybluez/pybluez)  
```sh
pip install pybluez
```

### Commands
PIP:
```sh
pip install DecimScanner
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
Donations are always appreciated! [Patreon](https://www.patreon.com/cinnamon1212)


## Other Repos
* [CyberSecurity Bot](https://github.com/Cinnamon1212/CyberSecDiscordBot)
* [LAN Pwning Toolkit](https://github.com/Cinnamon1212/LAN_Pwning_Toolkit)
* [BlueKit](https://github.com/Cinnamon1212/BlueKit)
