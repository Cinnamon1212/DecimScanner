import threading
import logging
import random
from queue import Queue
from scapy.all import IP, TCP, sr1, sr, ICMP, srp, Ether, ARP, UDP, send, srp1
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


q = Queue()
results = {}


class utils:
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


class scanners:

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
        packet = IP(dst=target)/ICMP()
        response = sr1(packet, timeout=float(t), verbose=0)

        if response is None:
                if target in results:
                    results[target].append("offline")
                else:
                    results[target] = []
                    results[target].append("offline")

        elif response.haslayer(ICMP):
            ICMPLayer = response.getlayer(ICMP)
            if int(ICMPLayer.type) == 0:
                if target in results:
                    results[target].append("online")
                else:
                    results[target] = []
                    results[target].append("online")
            elif int(ICMPLayer.type) == 3:
                if target in results:
                    results[target].append("offline", "destination unreachable")
                else:
                    results[target] = []
                    results[target].append("offline", "destination unreachable")

            elif int(ICMPLayer.type) == 5:
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
        pass


class threaders:


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

class TCPScans:
    """
SYN Scan - Connect to a target using a SYN flag and instantly sending a RST flag (Also known as stealth scan)
FIN Scan - Connect to a target using a FIN flag
Null Scan - Connect to a target using a NULL/0 header
ACK Scan - Connect to a target using an ACK flag
XMAS Scan - Uses FIN, PSH and URG flags to connect
Window Scan - The same as ACK scan except checks window size to determine if the port is open or closed
Idle Scan - Spoofs the connect to make it look like it's coming from the zombie
    """
    def __init__():
        global results
        results = {}

    def SYNScan(targets, ports=None, timeout=3, max_threads=30):
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

    def FINScan(targets, ports=None, timeout=3, max_threads=30):
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

    def NullScan(targets, ports=None, timeout=3, max_threads=30):
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

    def ACKScan(targets, ports=None, timeout=3, max_threads=30):
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

    def XMASScan(targets, ports=None, timeout=3, max_threads=30):
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

    def WindowScan(targets, ports=None, timeout=3, max_threads=30):
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

    def IdleScan(targets, zombie, ports=None, timeout=3, max_threads=30):
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

    def ping(targets, timeout=3, max_threads=3):
        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.ICMPPing_threader)
            t.daemon = True
            t.start()
        targets = utils.ValidateTargets(targets)
        for target in targets:
            worker = [target, timeout]
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
            ports = list(range(1, 256)

        for target in targets:
            for port in ports:
                worker = [target, port, timeout]
                q.put(worker)
        q.join()
        return results
