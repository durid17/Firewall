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
        self.connections = dict()
        self.c = 10
	
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
        result = False
        if(rule[0] == "pass"): result = True
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


    def log_rule(self, rule , packet, pkt , pkt_dir):
        # return True
        if(packet.transport != "tcp" or packet.port != 80): return None
        
        header_length, = struct.unpack("!B" , pkt[0:1])
        header_length = header_length & 15 #last four bits
        header_length = header_length * 4 #word length

        hostname = ""
        if pkt_dir == PKT_DIR_OUTGOING:
            hostname = socket.inet_ntoa(pkt[16:20])
        elif pkt_dir == PKT_DIR_INCOMING:
            hostname = socket.inet_ntoa(pkt[12:16])

        tcp = pkt[header_length:]
        tcp_header_length ,  = struct.unpack("!B" , tcp[12:13])
        tcp_header_length = tcp_header_length >> 4
        tcp_header_length = tcp_header_length * 4
        print(header_length , tcp_header_length)
        print(tcp[tcp_header_length:])
        http = tcp[tcp_header_length:]
        words = http.split()
        words = filter(lambda a: a != "", words)
        words = [x.lower() for x in words]
        if(len(words) < 2): return True
        if("host:" in words):
            hostname = words[words.index("host:") + 1]
        
        if(rule[2][0] == '*'):
            if(not hostname.endswith(rule[2][1:])): return None
        else:
            if(hostname != rule[2]): return None
        
        if(pkt_dir == PKT_DIR_OUTGOING):
            if(len(words) > 0): self.connections[packet.int_port] = (struct.unpack("!I" , tcp[8:12]),  words[words.index("host:") + 1] , words[0] , words[1] , words[2])
            return True

        if(packet.int_port not in self.connections): return None     
        
        seqnumber = struct.unpack("!I" , tcp[4:8])
        content_length = -1
        if("content-length:" in words): content_length = words[words.index("content-length:") + 1]

        # if(seqnumber > self.connections[packet.int_port][0]): return False
        # if(seqnumber < self.connections[packet.int_port][0]): return True

        if(len(words) < 2): return True
        try: 
            int(words[1])
            f = open('http.log' ,  'a')
            log = "" + str(self.connections[packet.int_port][1]) + " " +  str(self.connections[packet.int_port][2])
            log = log + " " + str(self.connections[packet.int_port][3]) + " " +  str(self.connections[packet.int_port][4])
            log = log + " " + str(words[1]) + " " +  str(content_length)
            f.write(log + "\n")
            f.flush()
            f.close()
            return True
        except:
            return True

    def check_rule(self, rule , packet, pkt  , pkt_dir):
        if(rule[0] == "log"): return self.log_rule(rule, packet , pkt , pkt_dir)
        if(rule[1] == "dns"): return self.check_dns_rule(rule , packet)
        if(packet.transport != rule[1]): return None
        result = False
        if(rule[0] == "pass"): result = True

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
    
    def send_deny_packet(self , rule , pkt , packet, pkt_dir):
        print("deny")
        if(packet.transport == "tcp"):
            print("tcp")
            if pkt_dir == PKT_DIR_OUTGOING:
                self.iface_int.send_ip_packet(packet.deny_tcp)
            elif pkt_dir == PKT_DIR_INCOMING:
                self.iface_ext.send_ip_packet(packet.deny_tcp)            
        elif (packet.transport == "udp" and packet.port == 53 and packet.qtype == 1):
            self.iface_int.send_ip_packet(packet.deny_dns(pkt))
    
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        packet = Packet(pkt , pkt_dir)
        print("transport" , packet.transport)
        print("port" , packet.port)
        print("domain" , packet.domain)
        print("ext_ip" , packet.ext_ip)
        print("qtype" , packet.qtype)
        for rule in self.rules:
            res = None
            try:
                res = self.check_rule(rule , packet , pkt, pkt_dir)
            except:
                pass
            print("result" , res)
            if(res == None): continue
            if(res):
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_int.send_ip_packet(pkt)
                elif pkt_dir == PKT_DIR_OUTGOING:
                    self.iface_ext.send_ip_packet(pkt)
            elif (rule[0] == "deny"):
                self.send_deny_packet(rule , pkt , packet , pkt_dir)
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
        self.deny_tcp = ""
        self.qtype = 0
        self.get_info(pkt,pkt_dir)

    def get_info(self , pkt, pkt_dir):
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
            self.compute_deny_tcp(pkt , header_length)
        elif(self.transport == 17):
            self.transport = "udp"
            self.parse_udp(data , pkt_dir)

    def compute_deny_tcp(self , pkt , header_length):
        header_length, = struct.unpack("!B" , pkt[0:1])
        header_length = header_length & 15 #last four bits
        header_length = header_length * 4 #word length  
        old_tcp = pkt[header_length:]

        new_pkt = struct.pack("!B" , 69)
        new_pkt += pkt[1:2]
        new_pkt += struct.pack("!H" , 40)
        new_pkt += pkt[4:8]
        new_pkt += struct.pack("!B" , 64) #ttl
        new_pkt += struct.pack("!B" , 6) #protocol
        new_pkt += struct.pack("!H" , 0) 
        new_pkt += pkt[16:20]
        new_pkt += pkt[12:16]
        checksum = self.count_check_sum(new_pkt)
        new_pkt = new_pkt[:10] + struct.pack("!H" , checksum) + new_pkt[12:]

        tcp = old_tcp[2:4] + old_tcp[0:2] + old_tcp[8:12] + struct.pack("!I" , struct.unpack("!I" , old_tcp[4:8])[0] + 1)
        tcp += struct.pack("!B" , 5 << 4) + struct.pack("!B" , 22) + old_tcp[14:16]
        tcp += struct.pack("!I" , 0)
        
        checksum = self.count_check_sum(tcp + pkt[12:20] + struct.pack("!BBH" , 0 , 6 , 20))
        tcp = tcp[:16] + struct.pack("!H" , checksum) + tcp[18:]
        new_pkt += tcp
        self.deny_tcp = new_pkt

    def parse_icmp(self , data):
        self.port, = struct.unpack("!B" , data[0:1])
    
    def parse_tcp(self , data, pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.port, = struct.unpack("!H" , data[0:2])
            self.int_port, = struct.unpack("!H" , data[2:4])
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.port, = struct.unpack("!H" , data[2:4])
            self.int_port, = struct.unpack("!H" , data[0:2])

    def parse_udp(self , data , pkt_dir):
        if pkt_dir == PKT_DIR_INCOMING:
            self.port, = struct.unpack("!H" , data[0:2])
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.port, = struct.unpack("!H" , data[2:4])
        
        if (self.port == 53): self.parse_dns(data[8:])

    def parse_dns(self , data):
        _ , options , QDCOUNT , _ , _  , _ = struct.unpack('!HHHHHH' , data[:12])
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
        self.qtype, = struct.unpack("!H" , data[ind:ind + 2])
        return name[1:] 

    def deny_dns(self, pkt):
        header_length, = struct.unpack("!B" , pkt[0:1])
        header_length = header_length & 15 #last four bits
        header_length = header_length * 4 #word length
        udp = pkt[header_length:]
        dns = udp[8:]
        new_dns = dns[0:2]
        flags, = struct.unpack("!H" , dns[2:4])
        flags = flags | (1 << 15)
        flags = flags & (2**16 - 1)
        new_dns += struct.pack("!H" , flags)
        new_dns += struct.pack("!H" , 1)
        new_dns += struct.pack("!H" , 1)
        new_dns += struct.pack("!H" , 0)
        new_dns += struct.pack("!H" , 0)
        for _ in range(0 , 2):
            ind = 12
            while True:
                length = struct.unpack('!B' , dns[ind:ind + 1])[0]
                new_dns += dns[ind:ind + 1]
                ind += 1
                if(length == 0): break
                new_dns += dns[ind:ind + length]
                ind += length
            new_dns += struct.pack("!H" , 1)
            new_dns += struct.pack("!H" , 1)
        
        new_dns += struct.pack("!I" , 1)
        new_dns += struct.pack("!H" , 4)
        new_dns += socket.inet_aton("169.229.49.130")
        udp = udp[2:4] + udp[0:2] + struct.pack("!H" , len(new_dns) + 8) + struct.pack("!H" , 0) + new_dns
        check_sum = self.count_check_sum(pkt[12:20] + struct.pack("!B" , 0) + struct.pack("!B" , 17) + struct.pack("!H" , len(udp)) + udp)
        print(check_sum)
        udp = udp[0:6] + struct.pack("!H" , check_sum) + udp[8:]
        total_length = len(udp) + header_length
        pkt = pkt[0:2] + struct.pack("!H" , total_length) + pkt[4 : 8] + struct.pack("!B" , 1) + pkt[9:10] + struct.pack("!H" , 0) + pkt[16:20] + pkt[12:16] + udp
        check_sum = self.count_check_sum(pkt[:header_length])
        pkt = pkt[0:10] + struct.pack("!H" , check_sum) + pkt[12:]
        return pkt

    def count_check_sum(self, data):
        sz = len(data)
        sum = long(0)
        i = 0
        while(i < sz):
            word16, = struct.unpack("!H" , data[i : i + 2])
            sum += word16
            i += 2
        while (sum >> 16 > 0):
            sum = (sum & 65535) + (sum >> 16)
        return ~sum & 65535
