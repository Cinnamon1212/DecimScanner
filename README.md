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
```pip3 install scapy ```
* [Python3](https://www.python.org/)   
```apt install python3 ```

### Python example
**Format: DecimScanner.(ScanPlatform/Protocol).(ScanType)**

```py  
import DecimScanner  
RandomlyGeneratedIPs = ["91.141.119.216", "204.45.197.227", "76.145.131.209", "112.77.12.53" ,"25.98.239.105"]
ports = [21, 22, 80, 443]   
scan = DecimScanner.TCPScans.FINScan(RandomlyGeneratedIPs, ports, timeout=0.5, max_threads=50)  
```
