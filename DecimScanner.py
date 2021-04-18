import threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from queue import Queue
from scapy.all import IP, TCP, sr1, sr, ICMP, srp, Ether, ARP, UDP, Raw

q = Queue()
results = {}

class scanners:

    def TCPSYNScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        global results
        packet = IP(dst=target)/TCP(dport=port, flags='S')
        response = sr1(packet, timeout=float(t), verbose=0)
        if response is not None:
            if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                sr(IP(dst=target)/TCP(dport=response.sport, flags='R'), timeout=float(t), verbose=0)
                if target in results:
                    results[target].append([port, "open"])
                else:
                    results[target] = []
                    results[target].append([port, "open"])
            else:
                if target in results:
                    results[target].append([port, "closed"])
                else:
                    results[target] = []
                    results[target].append([port, "closed"])
        else:
            if target in results:
                results[target].append([port, "closed"])
            else:
                results[target] = []
                results[target].append([port, "closed"])


    def ACKScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        global results
        packet = IP(dst=target)/TCP(dport=port, flags="A")
        response = sr1(packet, verbose=0, timeout=float(t), retry=2)
        if response is None:
            if target in results:
                results[target].append([port, "filtered"])
            else:
                results[target] = []
                results[target].append([port, "filtered"])
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


    def ARPPing(worker):
        target = worker[0]
        t = worker[1]
        PDST = worker[2]
        packet = Ether(dst=target)/ARP(pdst=PDST)
        ans, unans = srp(packet, timeout=float(t), verbose=0, retry=2)
        pass


    def SimpleUDPScan(worker):
        target = worker[0]
        port = worker[1]
        t = worker[2]
        global results
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


    def ARPPing_threader():
        while True:
            worker = q.get()
            scanners.ARPPing(worker)
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


class NetworkScan:
    def __init__():
        pass


    def TCPScans(scan_type: str, IPs, ports=None, timeout=3, max_threads=30):

        global results
        results = {}

        if isinstance(ports, int):
            ports = list(ports)
        elif isinstance(ports, str):
            if "-" in ports:
                port_range = ports.split("-")
                ports = list(range(int(port_range[0]), int(port_range[1]) + 1))
            elif "," in ports:
                ports = [int(i) for i in ports.split(',')]
        elif ports is None:
            ports = list(range(1, 1001))

        if scan_type == "SYN":
            for _ in range(max_threads + 1):
                t = threading.Thread(target=threaders.TCPSYNScan_threader)
                t.daemon = True
                t.start()

            if isinstance(ports, str):
                ports_str = ports.split("-")
                start = int(ports_str[0])
                end = int(ports_str[1]) + 1
                ports = list(range(start, end))
            for IP in IPs:
                for port in ports:
                    worker = [IP, port, timeout]
                    q.put(worker)
            q.join()
            return results



        elif scan_type == "FIN":
            for _ in range(max_threads + 1):
                t = threading.Thread(target=threaders.TCPFINScan_threader)
                t.daemon = True
                t.start()

            if isinstance(ports, str):
                ports_str = ports.split("-")
                start = int(ports_str[0])
                end = int(ports_str[1]) + 1
                ports = list(range(start, end))
            for IP in IPs:
                for port in ports:
                    worker = [IP, port, timeout]
                    q.put(worker)
                q.join()
                return results

        elif scan_type == "Null":
            for _ in range(max_threads + 1):
                t = threading.Thread(target=threaders.TCPNullScan_threader)
                t.daemon = True
                t.start()

            if isinstance(ports, str):
                ports_str = ports.split("-")
                start = int(ports_str[0])
                end = int(ports_str[1]) + 1
                ports = list(range(start, end))
            for IP in IPs:
                for port in ports:
                    worker = [IP, port, timeout]
                    q.put(worker)
                q.join()
                return results

        elif scan_type == "ACK":
            for x in range(max_threads + 1):
                t = threading.Thread(target=threaders.ACKScan_threader)
                t.daemon = True
                t.start()

            for IP in IPs:
                for port in ports:
                    worker = [IP, port, timeout]
                    q.put(worker)
            q.join()
            return results

        elif scan_type == "XMAS":
            for x in range(max_threads + 1):
                t = threading.Thread(target=threaders.XMASScan_threader)
                t.daemon = True
                t.start()

            for IP in IPs:
                for port in ports:
                    worker = [IP, port, timeout]
                    q.put(worker)
            q.join()
            return results


    def ARPScans(scan_type: str, IPs, PDST, timeout=3, max_threads=30):

        global results
        results = {}

        for x in range(max_threads + 1):
            t = threading.Thread(target=threaders.ARPPing_threader)
            t.daemon = True
            t.start()

        for IP in IPs:
            worker = [IP, timeout, PDST]
            q.put(worker)
        q.join()
        return results


    def UDPScans(scan_type: str, IPs, port, timeout=3, max_threads=30):

        global results
        results = {}

        if scan_type == "UDPConnect":
            for x in range(max_threads + 1):
                t = threading.Thread(target=threaders.SimpleUDPScan_threader)
                t.daemon = True
                t.start()

            for IP in IPs:
                for port in ports:
                    worker = [IP, port, timeout]
                    q.put(worker)
            q.join()
            return results


    def ICMPScans(scan_type: str, IPs, timeout=3, max_threads=30):

        global results
        results = {}

        if scan_type == "ping":
            for x in range(max_threads + 1):
                t = threading.Thread(target=threaders.ICMPPing_threader)
                t.daemon = True
                t.start()

            for IP in IPs:
                worker = [IP, timeout]
                q.put(worker)
            q.join()
            return results
