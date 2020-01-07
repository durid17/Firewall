#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import struct
import socket


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.rules = []
        self.countries = []
	
        rule_filename = config['rule']
        if(rule_filename == None): rule_filename = "rules.conf"
        self.get_rules(rule_filename)
        self.get_countries()

    def get_countries(self):
        with open("geoipdb.txt") as fp:
            for line in fp:
                words = line.strip().split(" ")
                words = filter(lambda a: a != "", words)
                words = [x.lower() for x in words]
                self.countries.append(words)

    def get_rules(self, rule_filename):
        with open(rule_filename) as fp:
            for line in fp:
                words = line.strip().split(" ")
                words = filter(lambda a: a != "", words)
                words = [x.lower() for x in words]
                if(len(words) == 0 or words[0][0] == '%'): continue
                self.rules.append(words)

    def check_dns_rule(self, rule , packet):
        result = True
        if(rule[0] == "drop"): result = False
        if(packet.port != 53): return None
        if(rule[2][0] == '*'):
            if(packet.domain.endswith(rule[2][1:])): return result
        elif (packet.domain == rule[2]): return result
        
        return None

    def check_port(self , result , rule_port , port):
        if(rule_port == "any"): return result
        port = int(port)
        if("-" in rule_port):
            start = int(rule_port.split("-")[0])
            end = int(rule_port.split("-")[1])
            if(port >= start and port <= end): return result
        else:
            if(port == int(rule_port)): return result

        return None
    
    def ip_to_int(self, addr):
        return struct.unpack("!I", socket.inet_aton(addr))[0]

    def check_country(self , result , rule , packet):
        ip = self.ip_to_int(packet.ext_ip)
        l = 0
        r = len(self.countries)
        res = -1
        while(l <= r):
            m = (l + r) / 2
            if(self.ip_to_int(self.countries[m][0]) <= ip):
                l = m + 1
                res = m
            else:
                r = m - 1
        if(res == -1): return None
        if(self.ip_to_int(self.countries[res][1]) < ip): return None
        if(self.countries[res][2] != rule[2]): return None
        return self.check_port(result , rule[3] , packet.port)

    def check_rule(self, rule , packet):
        if(rule[1] == "dns"): return self.check_dns_rule(rule , packet)
        
        if(packet.transport != rule[1]): return None
        result = True
        if(rule[0] == "drop"): result = False

        if("/" in rule[2]):
            ip = int(self.ip_to_int(packet.ext_ip))
            netip = int(self.ip_to_int(rule[2].split("/")[0]))
            mask = 32 - int(rule[2].split("/")[1])
            netmask = 2 ** 32 - 1
            netmask = (netmask >> mask) << mask     
            if ((netip & netmask) == (ip & netmask)):
                return self.check_port(result , rule[3] , packet.port)
            else: return None
        elif (len(rule[2]) == 2):
            return self.check_country(result , rule, packet)
        elif (rule[2] == "any"):
            return self.check_port(result , rule[3] , packet.port)
        elif (rule[2] == packet.ext_ip):
            return self.check_port(result , rule[3] , packet.port)

        return None

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        packet = Packet(pkt , pkt_dir)

        for rule in self.rules:
            res = self.check_rule(rule , packet)
            if(res == None): continue
            if(res):
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_ext.send_ip_packet(pkt)
            return

        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
        

class Packet:
    def __init__(self , pkt , pkt_dir):
        self.transport = 0
        self.port = 0
        self.domain = ""
        self.ext_ip = ""
        self.get_info(pkt,pkt_dir)

    def get_info(self , pkt,pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.ext_ip =  socket.inet_ntoa(pkt[12:16])
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.ext_ip =  socket.inet_ntoa(pkt[16:20])
        self.transport, = struct.unpack("!B" , pkt[9:10])
        header_length, = struct.unpack("!B" , pkt[0:1])
        header_length = header_length & 15 #last four bits
        header_length = header_length * 4 #word length
        total_length, = struct.unpack("!H" , pkt[2:4])
        data = pkt[header_length:]
        if(self.transport == 1):
            self.transport = "icmp"
            self.parse_icmp(data)
        elif(self.transport == 6):
            self.transport = "tcp"
            self.parse_tcp(data , pkt_dir)
        elif(self.transport == 17):
            self.transport = "udp"
            self.parse_udp(data , pkt_dir)

    def parse_icmp(self , data):
        self.port, = struct.unpack("!B" , data[0:1])
    
    def parse_tcp(self , data, pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.port, = struct.unpack("!H" , data[0:2])
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.port, = struct.unpack("!H" , data[2:4])

    def parse_udp(self , data , pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.port, = struct.unpack("!H" , data[0:2])
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.port, = struct.unpack("!H" , data[2:4])
        if (self.port == 53): self.parse_dns(data[8:])

    def parse_dns(self , data):
        _ , options , QDCOUNT , _ , _  , _ = struct.unpack('!HHHHHH' , data[:12])
        if (options >> 15 == 0 and QDCOUNT != 1): self.failed = True
        if (options >> 15 == 0 and QDCOUNT == 1): self.domain = self.get_name(data , 12).lower()

    def get_name(self , data , ind):
        name = ""
        while True:
            len = struct.unpack('!B' , data[ind:ind + 1])[0]
            ind += 1
            if(len == 0): break
            name = name + '.'
            for _ in range(0 , len):
                c = struct.unpack('!b' , data[ind:ind + 1])[0]
                name = name + chr(c)
                ind += 1
        return name[1:] 
