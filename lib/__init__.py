import threading
import os
import socket
import requests
import logging
import re
#  import matplotlib (for silencing GDK_IS_DISPLAY)
import datetime
import bluetooth
from bs4 import BeautifulSoup
from queue import Queue
from scapy.all import IP, TCP, sr1, sr, ICMP, srp, Ether, ARP, UDP, send, srp1, \
    ISAKMP, ISAKMP_payload_SA, ISAKMP_payload_Proposal, RandShort, DNS, DNSQR, \
    DNSRR, DNSRRSOA, DNSRRMX

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
#  matplotlib.use('Agg')

q = Queue()
results: dict = {}  # {ip: [reuslt]}
WebDirs: dict = {}  # {url: [dir]}
Crawled: dict = {}  # {url: [link]}
WebResponses: dict = {}  # {url: [response]}
UserPasses: dict = {}   # {ip: [user, pass, port]}
CurrentDepth = 0  # For web crawler

class utils:
    """
Repitive processes
    """
    def ValidateTargets(targets):
        if isinstance(targets, str):
            if "," in targets:
                targets = targets.split(",")
            else:
                targets = targets.split(" ")
            return targets
        elif isinstance(targets, list):
            return targets
        else:
            raise ValueError("IPs must be a string or list")

    def ValidatePorts(ports):
        if isinstance(ports, int):
            ports = [ports]
        elif isinstance(ports, str):
            if "-" in ports:
                port_range = ports.split("-")
                ports = list(range(int(port_range[0]), int(port_range[1]) + 1))
            elif "," in ports:
                ports = [int(i) for i in ports.split(',')]
            else:
                raise ValueError("Invalid port string, please split a range using '-' and list using ','")
        elif ports is None:
            ports = list(range(1, 1001))
        return ports

    def ValidateURL(urls):
        regex = ("((http|https)://)(www.)?" +
                 "[a-zA-Z0-9@:%._\\+~#?&//=]" +
                 "{2,256}\\.[a-z]" +
                 "{2,6}\\b([-a-zA-Z0-9@:%" +
                 "._\\+~#?&//=]*)")
        reg = re.compile(regex)
        if isinstance(urls, str):
            if "," in urls:
                urls.split(",")
            elif " " in urls:
                urls.split(" ")
            else:
                urls = [urls]
        elif isinstance(urls, int):
            raise ValueError("URLs cannot be integers")

        validurls = []
        for url in urls:
            if re.search(reg, url):
                validurls.append(url)
        return validurls

    def FindLinks(URL, start_url, t, UA):
        headers = requests.utils.default_headers()
        headers.update({'User-Agent': UA})
        try:
            r = requests.get(URL, timeout=float(t), headers=headers)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                links = [x.get('href') for x in soup.find_all(href=True)]
                return links
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.MissingSchema:
            pass

    def ValidatePassfile(passfile):
        passwords = []
        if os.path.exists(passfile):
            with open(passfile, "r") as password_file:
                pass_list = password_file.read()
                for password in pass_list:
                    passwords.append(password.strip())
        else:
            raise FileNotFoundError(f"Unable to find {passfile}")
        return passwords

    def ValidateUserfile(userfile):
        usernames = []
        if os.path.exists(userfile):
            with open(userfile, "r") as username_file:
                userlist = username_file.read()
                for user in userlist:
                    if user not in userlist:
                        usernames.apppend(user.strip())
        else:
            raise FileNotFoundError(f"Unable to find {userfile}")

        return usernames

    def ValidateUsernames(usernames):
        if isinstance(usernames, str):
            if "," in usernames:
                usernames = usernames.split(",")
            elif " " in usernames:
                usernames = usernames.split(" ")
            else:
                usernames = [usernames]
        elif isinstance(usernames, int) or isinstance(usernames, float):
            usernames = [str(usernames)]

        return usernames

    def ValidatePasswords(passwords):
        if isinstance(passwords, str):
            raise ValueError("Unable to split comma seperated passwords, please provide a list")
        elif isinstance(passwords, int) or isinstance(passwords, float):
            passwords = [str(passwords)]
        return passwords


class scanners:
    """
All scanners (Network, bluetooth, WiFi and other)
    """

    def TCPSYNScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        global results
        packet = IP(dst=target)/TCP(dport=port, flags='S')
        response = sr1(packet, timeout=float(t), verbose=0, retry=2)
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == "SA":
                sr(IP(dst=target)/TCP(dport=response.sport, flags='R'), timeout=float(t), verbose=0)
                if target in results:
                    results[target].append([port, "open"])
                else:
                    results[target] = []
                    results[target].append([port, "open"])
            elif response.haslayer(TCP) and response.getlayer(TCP).flags == "RA":
                if target in results:
                    results[target].append([port, "closed"])
                else:
                    results[target] = []
                    results[target].append([port, "closed"])
            elif response.haslayer(ICMP):
                ICMPLayer = response.getlayer(ICMP)
                if int(ICMPLayer.type) == 3 and int(ICMPLayer.code) in [1, 2, 3, 9, 10, 13]:
                    if target in results:
                        results[target].append([port, "filtered"])
                    else:
                        results[target] = []
                        results[target].append([port, "filtered"])
        else:
            if target in results:
                results[target].append([port, "unresponsive"])
            else:
                results[target] = []
                results[target].append([port, "unresponsive"])

    def ACKScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        global results
        packet = IP(dst=target)/TCP(dport=port, flags="A")
        response = sr1(packet, verbose=0, timeout=float(t), retry=2)
        if response is None:
            if target in results:
                results[target].append([port, "unresponsive"])
            else:
                results[target] = []
                results[target].append([port, "unresponsive"])
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
            if target in results:
                results[target].append([port, "unfiltered"])
            else:
                results[target] = []
                results[target].append([port, "unfiltered"])
        elif response.haslayer(ICMP):
            ICMPLayer = response.getlayer(ICMP)
            if int(ICMPLayer.type) == 3 and int(ICMPLayer.code) in [1, 2, 3, 9, 10, 13]:
                if target in results:
                    results[target].append([port, "filtered"])
                else:
                    results[target] = []
                    results[target].append([port, "filtered"])

    def XMASScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        packet = IP(dst=target)/TCP(dport=port, flags="FPU")
        response = sr1(packet, verbose=0, timeout=float(t), retry=2)
        if response is None:
            if target in results:
                results[target].append([port, "open/filtered"])
            else:
                results[target] = []
                results[target].append([port, "open/filtered"])

        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 'RA':
            if target in results:
                results[target].append([port, "closed"])
            else:
                results[target] = []
                results[target].append([port, "closed"])

        elif response.haslayer(ICMP):
            ICMPLayer = response.getlayer(ICMP)
            if int(ICMPLayer.type) == 3 and int(ICMPLayer.code) in [1, 2, 3, 9, 10, 13]:
                if target in results:
                    results[target].append([port, "filtered"])
                else:
                    results[target] = []
                    results[target].append([port, "filtered"])
        else:
            if target in results:
                results[target].append([port, "closed"])
            else:
                results[target] = []
                results[target].append([port, "closed"])

    def SimpleUDPScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        packet = IP(dst=target)/UDP(dport=port)
        response = sr1(packet, verbose=0, timeout=t, retry=2)

        if response is None:
            if target in results:
                results[target].append([port, "open/filtered"])
            else:
                results[target] = []
                results[target].append([port, "open/filtered"])

        elif(response.haslayer(ICMP)):
            ICMPLayer = response.getlayer(ICMP)
            if int(ICMPLayer.type) == 3 and int(ICMPLayer.code) == 3:
                if target in results:
                    results[target].append([port, "closed"])
                else:
                    results[target] = []
                    results[target].append([port, "closed"])
            elif int(ICMPLayer.type) == 3 and int(ICMPLayer.code) in [1, 2, 9, 10, 13]:
                if target in results:
                    results[target].append([port, "closed"])
                else:
                    results[target] = []
                    results[target].append([port, "closed"])
        elif response is not None:
            if target in results:
                results[target].append([port, "open"])
            else:
                results[target] = []
                results[target].append([port, "open"])

    def ICMPPing(worker):
        target = worker[0]
        t = worker[1]
        verbose = worker[2]
        packet = IP(dst=target)/ICMP()
        response = sr1(packet, timeout=float(t), verbose=0)

        if response is None:
            if verbose is True:
                print(f"[-] {target} is offline")
            if target in results:
                results[target].append("offline")
            else:
                results[target] = []
                results[target].append("offline")
        elif response.haslayer(ICMP):
            ICMPLayer = response.getlayer(ICMP)
            if int(ICMPLayer.type) == 0:
                if verbose is True:
                    print(f"[-] {target} is online")
                if target in results:
                    results[target].append("online")
                else:
                    results[target] = []
                    results[target].append("online")
            elif int(ICMPLayer.type) == 3:
                if verbose is True:
                    print(f"[!] {target} destination unreachable")
                if target in results:
                    results[target].append("offline", "destination unreachable")
                else:
                    results[target] = []
                    results[target].append("offline", "destination unreachable")

            elif int(ICMPLayer.type) == 5:
                if verbose is True:
                    print(f"[*] {target} redirected")
                if target in results:
                    results[target].append("offline", "redirect")
                else:
                    results[target] = []
                    results[target].append("offline", "redirect")

    def TCPFINScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        packet = IP(dst=target)/TCP(dport=port, flags="F")
        response = sr1(packet, verbose=0, timeout=float(t))
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 'RA':
                if target in results:
                    results[target].append([port, "closed"])
                else:
                    results[target] = []
                    results[target].append([port, "closed"])
            elif response.haslayer(ICMP):
                ICMPLayer = response.getlayer(ICMP)
                if int(ICMPLayer.type) == 3 and int(ICMPLayer.code) in [1, 2, 3, 9, 10, 13]:
                    if target in results:
                        results[target].append([port, "filtered"])
                    else:
                        results[target] = []
                        results[target].append([port, "filtered"])
        else:
            if target in results:
                results[target].append([port, "open"])
            else:
                results[target] = []
                results[target].append([port, "open"])

    def TCPNullScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        packet = IP(dst=target)/TCP(dport=port, flags=0)
        response = sr1(packet, verbose=0, timeout=float(t))
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 'RA':
                if target in results:
                    results[target].append([port, "closed"])
                else:
                    results[target] = []
                    results[target].append([port, "closed"])
            elif response.haslayer(ICMP):
                ICMPLayer = response.getlayer(ICMP)
                if int(ICMPLayer.type) == 3 and int(ICMPLayer.code) in [1, 2, 3, 9, 10, 13]:
                    if target in results:
                        results[target].append([port, "filtered"])
                    else:
                        results[target] = []
                        results[target].append([port, "filtered"])
        else:
            if target in results:
                results[target].append([port, "open"])
            else:
                results[target] = []
                results[target].append([port, "open"])

    def WindowScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        packet = IP(dst=target)/TCP(dport=port, flags='A')
        response = sr1(packet, timeout=float(t), verbose=0)
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).window == 0:
                if target in results:
                    results[target].append([port, "closed"])
                else:
                    results[target] = []
                    results[target].append([port, "closed"])
            else:
                if target in results:
                    results[target].append([port, "open"])
                else:
                    results[target] = []
                    results[target].append([port, "open"])
        else:
            if target in results:
                results[target].append([port, "unresponsive"])
            else:
                results[target] = []
                results[target].append([port, "unresponsive"])

    def IdleScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        zombie = worker[3]

        z_packet = IP(dst=zombie)/TCP(dport=port, flags='S')
        z_response = sr1(z_packet, verbose=0, timeout=float(t), retry=2)
        if z_response is not None:
            z_id = z_response.id
            spoofed = send(IP(dst=target, src=zombie)/TCP(dport=port, flags="S"), verbose=0)
            t_packet = IP(dst=zombie)/TCP(dport=port, flags="SA")
            t_response = sr1(t_packet, verbose=0, timeout=float(t), retry=2)
            if t_response is not None:
                final_id = t_response.id
                if final_id - z_id < 2:
                    if target in results:
                        results[target].append([port, "closed"])
                    else:
                        results[target] = []
                        results[target].append([port, "closed"])
                else:
                    if target in results:
                        results[target].append([port, "open"])
                    else:
                        results[target] = []
                        results[target].append([port, "open"])
            else:
                if target in results:
                    results[target].append([port, "unresponsive"])
                else:
                    results[target] = []
                    results[target].append([port, "unresponsive"])
        else:
            if target in results:
                results[target].append([port, "zombie unresponsive"])
            else:
                results[target] = []
                results[target].append([port, "zombie unresponsive"])

    def IPProtocolScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        packet = IP(dst=target, proto=port)
        response = sr1(packet, verbose=0, timeout=float(2), retry=2)
        if response is not None:
            if response.haslayer(ICMP):
                ICMPLayer = response.getlayer(ICMP)
                if int(ICMPLayer.type) == 3 and int(ICMPLayer.code) == 2:
                    if target in results:
                        results[target].append([port, "closed"])
                    else:
                        results[target] = []
                        results[target].append([port, "closed"])
                elif int(ICMPLayer.type) == 3 and int(ICMPLayer.code) in [1, 3, 9, 10, 13]:
                    if target in results:
                        results[target].append([port, "filtered"])
                    else:
                        results[target] = []
                        results[target].append([port, "filtered"])
                else:
                    if target in results:
                        results[target].append([port, "open"])
                    else:
                        results[target] = []
                        results[target].append([port, "open"])
            else:
                if target in results:
                    results[target].append([port, "open"])
                else:
                    results[target] = []
                    results[target].append([port, "open"])
        else:
            if target in results:
                results[target].append([port, "unresponsive"])
            else:
                results[target] = []
                results[target].append([port, "unresponsive"])

    def IKEScan(worker):
        target = worker[0]
        t = worker[1]
        packet = IP(dst=target)/UDP()/ISAKMP(init_cookie=RandString(8), exch_type="identity prot.")/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal())
        response = sr1(packet, verbose=0, timeout=float(t))
        if response is not None:
            if response.haslayer(ISAKMP):
                if target in results:
                    results[target].append(["Configured for IPsec", response])
                else:
                    results[target] = []
                    results[target].append(["Configured for IPsec", response])
            else:
                if target in results:
                    results[target].append("Not configured for IPsec")
                else:
                    results[target] = []
                    results[target].append("Not configured for IPsec")
        else:
            if target in results:
                results[target].append("unresponsive")
            else:
                results[target] = []
                results[target].append("unresponsive")

    def BluetoothServScan(worker):
        target = worker[0]
        services = bluetooth.find_service(address=target)
        if target in results:
            results[target].append(services)
        else:
            results[target] = []
            results[target].append(services)

    def DNSIPv4(worker):
        targetIP = worker[0]
        targetDNS = worker[1]
        t = worker[2]
        packet = IP(dst=targetIP)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=targetDNS, qtype="A"))
        response = sr1(packet, verbose=0, timeout=float(t))
        if response is not None:
            if response.haslayer(DNSRR):
                if targetIP in results:
                    results[targetIP].append([response.an.rrname.decode(), response.an.rdata])
                else:
                    results[targetIP] = []
                    results[targetIP].append([[response.an.rrname.decode(), response.an.rdata]])
            else:
                if targetIP in results:
                    results[targetIP].append("target online, but gave no DNS response")
                else:
                    results[targetIP] = []
                    results[targetIP].append("target online, but gave no DNS response")
        else:
            if targetIP in results:
                results[targetIP].append("target unresponsive")
            else:
                results[targetIP] = []
                results[targetIP].append("target unresponsive")

    def DNSSAO(worker):
        targetIP = worker[0]
        targetDNS = worker[1]
        t = worker[2]
        packet = IP(dst=targetIP)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=targetDNS, qtype="SOA"))
        response = sr1(packet, verbose=0, timeout=float(t))
        if response is not None:
            if response.haslayer(DNSRRSOA):
                if targetIP in results:
                    results[targetIP].append([response.ns.rname, response.ns.mname])
                else:
                    results[targetIP] = []
                    results[targetIP].append([response.ns.rname, response.ns.mname])
            else:
                if targetIP in results:
                    results[targetIP].append("target online, but gave no DNS response")
                else:
                    results[targetIP] = []
                    results[targetIP].append("target online, but gave no DNS response")
        else:
            if targetIP in results:
                results[targetIP].append("target unresponsive")
            else:
                results[targetIP] = []
                results[targetIP].append("target unresponsive")

    def DNSMX(worker):
        targetIP = worker[0]
        targetDNS = worker[1]
        t = worker[2]
        packet = IP(dst=targetIP)/UDP(sport=RandShort(), dport=53)/DNS(rd=1,qd=DNSQR(qname=targetDNS, qtype="MX"))
        response = sr1(packet, verbose=0, timeout=float(t))
        if response is not None:
            if response.haslayer(DNSRRMX):
                exchanges = [x.exchange.decode() for x in response.an.iterpayloads()]
                if targetIP in results:
                    results[targetIP].append(exchanges)
                else:
                    results[targetIP] = []
                    results[targetIP].append(exchanges)
            else:
                if targetIP in results:
                    results[targetIP].append("target online, but gave no DNS response")
                else:
                    results[targetIP] = []
                    results[targetIP].append("target online, but gave no DNS response")
        else:
            if targetIP in results:
                results[targetIP].append("target unresponsive")
            else:
                results[targetIP] = []
                results[targetIP].append("target unresponsive")

    def DNSTraceroute(worker):
        target = worker[0]
        t = worker[1]
        packet = IP(dst=target, ttl=(1, 10))/ICMP()
        response = sr1(packet, verbose=0, timeout=float(t), retry=2)
        if response is not None:
            if response.haslayer(IP) and response.haslayer(ICMP):
                IPLayer = response.getlayer(IP)
                ICMPLayer = response.getlayer(ICMP)
                if target in results:
                    results[target].append([IPLayer.src, ICMPLayer.type])
                else:
                    results[target] = []
                    results[target].append([IPLayer.src, ICMPLayer.type])
            else:
                if target in results:
                    results[target].append("target online, but gave an invalid response")
                else:
                    results[target] = []
                    results[target].append("target online, but gave an invalid response")
        else:
            if target in results:
                results[target].append("target unresponsive")
            else:
                results[target] = []
                results[target].append("target unresponsive")

    def UDPTraceroute(worker):
        target = worker[0]
        queryname = worker[1]
        t = worker[2]
        packet = IP(dst=target, ttl=(1,20))/UDP()/DNS(qd=DNSQR(qname=queryname))
        response = sr1(packet, verbose=0, timeout=float(t), retry=2)
        if response is not None:
            if response.haslayer(IP) and response.haslayer(ICMP):
                IPLayer = response.getlayer(IP)
                ICMPLayer = response.getlayer(ICMP)
                if target in results:
                    results[target].append([IPLayer.src, ICMPLayer.type])
                else:
                    results[target] = []
                    results[target].append([IPLayer.src, ICMPLayer.type])
            else:
                if target in results:
                    results[target].append("target online, but gave an invalid response")
                else:
                    results[target] = []
                    results[target].append("target online, but gave an invalid response")
        else:
            if target in results:
                results[target].append("target unresponsive")
            else:
                results[target] = []
                results[target].append("target unresponsive")

    def TCPSynTraceroute(worker):
        target = worker[0]
        t = worker[1]
        packet = IP(dst=target, ttl=(1,10))/TCP(dport=53, flags="S")
        response = sr1(packet, verbose=0, retry=2, timeout=float(t))
        if response is not None:
            if response.haslayer(IP) and response.haslayer(ICMP):
                if target in results:
                    results[target].append([])
                else:
                    results[target] = []
                    results[target].append([response.getlayer(IP).src, response.getlayer(ICMP).type])
            else:
                if target in results:
                    results[target].append("target online, but gave an invalid response")
                else:
                    results[target] = []
                    results[target].append("target online, but gave an invalid response")
        else:
            if target in results:
                results[target].append("target unresponsive")
            else:
                results[target] = []
                results[target].append("target unresponsive")

    def Gethostbyname(worker):
        target = worker[0]
        try:
            hostname = socket.gethostbyname(target)
            if target in results:
                results[target].append(hostname)
            else:
                results[target] = []
                results[target].append(hostname)
        except socket.gaierror:
            if target in results:
                results[target].append("target unresponsive")
            else:
                results[target] = []
                results[target].append("target unresponsive")

    def ServiceScan(worker):
        target = worker[0]
        port = worker[1]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            banner = s.recv(1024)
            if len(banner) == 0:
                if target in results:
                    results[target].append([port])
                else:
                    results[target] = []
                    results[target].append([port])
            else:
                if target in results:
                    results[target].append([port, banner.decode()])
                else:
                    results[target] = []
                    results[target].append([port, banner.decode()])
            s.close()
        except socket.gaierror:
            if target in results:
                results[target].append("target unresponsive")
            else:
                results[target] = []
                results[target].append("target unresponsive")
        except socket.timeout:
            if target in results:
                results[target].append("target timed out")
            else:
                results[target] = []
                results[target].append("target timed out")
        except socket.error:
            if target in results:
                results[target].append([port, "closed"])
            else:
                results[target] = []
                results[target].append([port, "closed"])





class WebScanners:

    def StatusCheck(worker):
        if len(worker) == 3:
            url = worker[0]
            status = worker[1]
            t = worker[2]
            try:
                r = requests.head(url, timeout=float(t))
                if isinstance(status, int):
                    if r.status_code == status:
                        WebResponses[url] = r.status_code
                else:
                    if r.status_code in status:
                        WebResponses[url] = r.status_code

            except requests.exceptions.Timeout:
                WebResponses[url] = "timed out"
            except requests.exceptions.ConnectionError:
                WebResponses[url] = "unresponsive"
        else:
            url = worker[0]
            t = worker[1]
            try:
                r = requests.head(url, timeout=float(t))
                WebResponses[url] = r.status_code
            except requests.exceptions.Timeout:
                WebResponses[url] = "timed out"
            except requests.exceptions.ConnectionError:
                WebResponses[url] = "unresponsive"

    def DirCheck(worker):
        URL = worker[0]
        Dir = worker[1]
        UA = worker[2]
        t = worker[3]
        verbose = worker[4]
        if URL[-1] and Dir[0] == "/":
            Dir = Dir[1:]
        full_path = f"{URL}{Dir}"
        headers = requests.utils.default_headers()
        headers.update({'User-Agent': UA})
        try:
            r = requests.head(full_path, timeout=float(t), headers=headers)
            if r.status_code != 404:
                if verbose is True:
                    with printlock:
                        print(f"[+] {full_path} : {r.status_code}")
                if URL in WebDirs:
                    WebDirs[URL].add((full_path, r.status_code))
                else:
                    WebDirs[URL] = set()
                    WebDirs[URL].add((full_path, r.status_code))
        except requests.exceptions.Timeout:
            WebResponses[URL] = "timed out"
        except requests.exceptions.ConnectionError:
            WebResponses[URL] = "unresponsive"

    def WebCrawl(worker):
        URL = worker[0]
        UA = worker[1]
        t = worker[2]
        depth = worker[3]
        verbose = worker[4]
        global CurrentDepth
        CurrentDepth = 0
        Crawled[URL] = []
        links = utils.FindLinks(URL, URL, t, UA)
        while CurrentDepth != depth:
            for x in links:
                if x not in Crawled[URL]:
                    if verbose is True:
                        with printlock:
                            print(f"New link: {x}")
                    Crawled[URL].append(x)
                    found_links = utils.FindLinks(x, URL, t, UA)
                    if found_links is not None:
                        for found_link in found_links:
                            if found_link not in Crawled[URL]:
                                Crawled[URL].append(found_link)
            CurrentDepth += 1


class threaders:
    """
Theaders for the different scanners
    """
    def TCPSYNScan_threader():
        while True:
            worker = q.get()
            scanners.TCPSYNScan(worker)
            q.task_done()

    def ACKScan_threader():
        while True:
            worker = q.get()
            scanners.ACKScan(worker)
            q.task_done()

    def XMASScan_threader():
        while True:
            worker = q.get()
            scanners.XMASScan(worker)
            q.task_done()

    def SimpleUDPScan_threader():
        while True:
            worker = q.get()
            scanners.SimpleUDPScan(worker)
            q.task_done()

    def ICMPPing_threader():
        while True:
            worker = q.get()
            scanners.ICMPPing(worker)
            q.task_done()

    def TCPFINScan_threader():
        while True:
            worker = q.get()
            scanners.TCPFINScan(worker)
            q.task_done()

    def TCPNullScan_threader():
        while True:
            worker = q.get()
            scanners.TCPNullScan(worker)
            q.task_done()

    def WindowScan_threader():
        while True:
            worker = q.get()
            scanners.WindowScan(worker)
            q.task_done()

    def IdleScan_threader():
        while True:
            worker = q.get()
            scanners.IdleScan(worker)
            q.task_done()

    def IPProtocolScan_threader():
        while True:
            worker = q.get()
            scanners.IPProtocolScan(worker)
            q.task_done()

    def IKEScan_threader():
        while True:
            worker = q.get()
            scanners.IKEScan(worker)
            q.task_done()

    def BluetoothServScan_threader():
        while True:
            worker = q.get()
            scanners.BluetoothServScan(worker)
            q.task_done()

    def DNSIPv4_threader():
        while True:
            worker = q.get()
            scanners.DNSIPv4(worker)
            q.task_done()

    def DNSSAO_threader():
        while True:
            worker = q.get()
            scanners.DNSSAO(worker)
            q.task_done()

    def DNSMX_threader():
        while True:
            worker = q.get()
            scanners.DNSMX(worker)
            q.task_done()

    def TCPSynTraceroute_threader():
        while True:
            worker = q.get()
            scanners.TCPSynTraceroute(worker)
            q.task_done()

    def UDPTraceroute_threader():
        while True:
            worker = q.get()
            scanners.UDPTraceroute(worker)
            q.task_done()

    def DNSTraceroute_threader():
        while True:
            worker = q.get()
            scanners.DNSTraceroute(worker)
            q.task_done()

    def Gethostbyname_threader():
        while True:
            worker = q.get()
            scanners.Gethostbyname(worker)
            q.task_done()


    def StatusCheck_threader():
        while True:
            worker = q.get()
            WebScanners.StatusCheck(worker)
            q.task_done()

    def DirCheck_threader():
        while True:
            worker = q.get()
            WebScanners.DirCheck(worker)
            q.task_done()

    def WebCrawl_threader():
        while True:
            worker = q.get()
            WebScanners.WebCrawl(worker)
            q.task_done()

    def ServiceScan_threader():
        while True:
            worker = q.get()
            scanners.ServiceScan(worker)
            q.task_done()


class TCPScans:
    """
SYN Scan - Connect to a target using a SYN flag and instantly sending a RST flag (Also known as stealth scan)
FIN Scan - Connect to a target using a FIN flag
Null Scan - Connect to a target using a NULL/0 header
ACK Scan - Connect to a target using an ACK flag
XMAS Scan - Uses FIN, PSH and URG flags to connect
Window Scan - The same as ACK scan except checks window size to determine if the port is open or closed
Idle Scan - Spoofs the connect to make it look like it's coming from the zombie
Service Scan - Attempts to identify services running on a port
    """
    def __init__():
        global results
        results = {}

    def SYNScan(targets, ports=None, timeout=3, max_threads: int = 30):
        for _ in range(max_threads + 1):
            t = threading.Thread(target=threaders.TCPSYNScan_threader)
            t.daemon = True
            t.start()

        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)

        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
        q.join()
        return results

    def FINScan(targets, ports=None, timeout=3, max_threads: int = 30):
        for _ in range(max_threads + 1):
            t = threading.Thread(target=threaders.TCPFINScan_threader)
            t.daemon = True
            t.start()

        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)

        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
            q.join()
            return results

    def NullScan(targets, ports=None, timeout=3, max_threads: int = 30):
        for _ in range(max_threads + 1):
            t = threading.Thread(target=threaders.TCPNullScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)
        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
            q.join()
            return results

    def ACKScan(targets, ports=None, timeout=3, max_threads: int = 30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.ACKScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)
        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
        q.join()
        return results

    def XMASScan(targets, ports=None, timeout=3, max_threads: int = 30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.XMASScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)
        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
        q.join()
        return results

    def WindowScan(targets, ports=None, timeout=3, max_threads: int = 30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.WindowScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)
        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
        q.join()
        return results

    def IdleScan(targets, zombie, ports=None, timeout=3, max_threads: int = 30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.IdleScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)
        for target in targets:
            for port in ports:
                worker = [target, port, timeout, zombie]
                q.put(worker)
        q.join()
        return results

    def ServiceScan(targets, ports=None, timeout=3, max_threads: int = 30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.ServiceScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)
        socket.setdefaulttimeout(float(timeout))
        for target in targets:
            for port in ports:
                worker = [target, port]
                q.put(worker)
        q.join()
        return results

class UDPScans:
    """
UDPConnect - Connect to a port using UDP to check if it's open
    """
    def __init__():
        global results
        results = {}

    def UDPConnect(targets, ports=None, timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.SimpleUDPScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        ports = utils.ValidatePorts(ports)
        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
        q.join()
        return results


class ICMPScans:
    """
Ping - Ping a host/list of hosts to see if it's online
Protocol Scan - Determine open IP protocols

    """
    def __init__():
        global results
        results = {}


    def ping(targets, timeout=3, max_threads=3, verbose=False):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.ICMPPing_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            worker = [target, timeout, verbose]
            q.put(worker)
        q.join()
        return results


    def ProtocolScan(targets, ports=None, timeout=3, max_threads=3):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.IPProtocolScan_threader)
            t.daemon = True
            t.start()

        targets = utils.ValidateTargets(targets)
        if isinstance(ports, int):
            ports = [ports]
        elif isinstance(ports, str):
            if "-" in ports:
                port_range = ports.split("-")
                ports = list(range(int(port_range[0]), int(port_range[1]) + 1))
            elif "," in ports:
                ports = [int(i) for i in ports.split(',')]
            else:
                raise ValueError("Invalid port string, please split a range using '-' and list using ','")
        elif ports is None:
            ports = list(range(1, 256))

        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
        q.join()
        return results


class DNSScans:
    def __init__():
        global results
        results = {}

    def DNSIPv4(targets, targetDNSs=["test.com"], timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.DNSIPv4_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            for targetDNS in targetDNSs:
                worker = [target, targetDNS, timeout]
                q.put(worker)
        q.join()
        return results


    def DNSSAO(targets, targetDNSs=["test.com"], timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.DNSSAO_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            for targetDNS in targetDNSs:
                worker = [target, targetDNS, timeout]
                q.put(worker)
        q.join()
        return results


    def DNSMX(targets, targetDNSs=["test.com"], timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.DNSMX_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            for targetDNS in targetDNSs:
                worker = [target, targetDNS, timeout]
                q.put(worker)
        q.join()
        return results


class Traceroute:
    def __init__():
        global results
        results = {}

    def TCPSyn(targets, timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.TCPSynTraceroute_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            worker = [target, timeout]
            q.put(worker)
        q.join()
        return results

    def UDP(targets, queryname="test.com", timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.UDPTraceroute_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            worker = [target, queryname, timeout]
            q.put(worker)
        q.join()
        return results

    def DNS(targets, timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.DNSTraceroute_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            worker = [target, timeout]
            q.put(worker)
        q.join()
        return results


class BluetoothScans:
    def __init__():
        global results
        results = {}

    def GetNearby(duration=None, devicecount=None):
        devices = []
        if devicecount is not None and devicecount > 0:
            while len(devices) != devicecount:
                nearby = bluetooth.discover_devices(lookup_names=True)
                for x in nearby:
                    if x not in devices:
                        devices.append(x)
                    else:
                        pass
            return devices
        else:
            if duration is not None and duration > 0:  # Work around for bluetooth module finishing scan early
                endTime = datetime.datetime.now() + datetime.timedelta(seconds=duration)
                while True:
                    nearby = bluetooth.discover_devices(lookup_names=True)
                    for x in nearby:
                        if x not in devices:
                            devices.append(x)
                        else:
                            pass
                    if datetime.datetime.now() >= endTime:
                        break
                return devices
            else:
                raise ValueError("Duration and device count cannot be None or 0.")

    def ServiceScan(targets, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.BluetoothServScan_threader)
            t.daemon = True
            t.start()

        for target in targets:
            worker = [target]
            q.put(worker)
        q.join()
        return results


class OtherScans:
    def __init__():
        global results
        result = {}

    def IKEScan(targets, timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.IKEScan_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            worker = [target, timeout]
            q.put(worker)
        q.join()
        return results

    def Gethostbyname(targets, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.Gethostbyname_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            worker = [target]
            q.put(worker)
        q.join()
        return results


class WebScans:
    def __init__():
        global WebDirs, WebResponses
        WebDirs = set()
        WebResponses = {}

    def DirCheck(URLs, wordlist, timeout=3, max_threads=30, userAgent=None, verbose=False):
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"Unable to find {wordlist}")
        if userAgent is None:
            userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15 Version/13.0.4"
        URLs = utils.ValidateURL(URLs)
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.DirCheck_threader)
            t.daemon = True
            t.start()

        dirs_to_check = []
        with open(wordlist) as f:
            lines = f.readlines()
            for URL in URLs:
                for line in lines:
                    if line[0] == "#" or line == " ":
                        pass
                    else:
                        worker = [URL, line.strip(), userAgent, timeout, verbose]
                        q.put(worker)
            q.join()
            return WebDirs

        URLs = utils.ValidateTargets(URLs)

    def StatusCheck(URLs, status=None, timeout=3, max_threads=30):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.StatusCheck_threader)
            t.daemon = True
            t.start()

        if status is None:
            for URL in URLs:
                worker = [URL, timeout]
                q.put(worker)
        else:
            if hasattr(status, '__iter__'):
                if isinstance(status, str):
                    if "," in status:
                        status = status.split(",")
                    else:
                        status = status.split(" ")
                try:
                    int_status = []
                    for s in status:
                        s = int(s)
                        int_status.append(s)
                    status = int_status
                except ValueError:
                    raise ValueError("HTTP Status codes must be integers")
            for URL in URLs:
                worker = [URL, status, timeout]
                q.put(worker)
        q.join()
        return WebResponses

    def WebCrawl(URLs, timeout=3, max_threads=30, depth=3, userAgent=None, verbose=False):
        if userAgent is None:
            userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Safari/605.1.15 Version/13.0.4"

        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.WebCrawl_threader)
            t.daemon = True
            t.start()

        URLs = utils.ValidateURL(URLs)
        for URL in URLs:
            worker = [URL, userAgent, timeout, depth, verbose]
            q.put(worker)
        q.join()
        return WebDirs
