import struct
import dnsserver, consistenthash

class CHDNS(object):
    def __init__(self, ips):
        self.ring = consistenthash.HashRing(ips)
    
    def get_response(self, query, domain, qtype, qclass, src_addr):
        value = self.ring.get_node(query)
        print repr(value)
        answer = struct.pack("!I", dnsserver.ipstr2int(value))
        return 0, [{'qtype': qtype, 'qclass': qclass, 'ttl': 300, 'rdata': answer}]

dnsserver.config_files = {'x':{'domain': ['tor2web', 'org'], 'source': CHDNS([
  '1.1.1.1', '2.2.2.2', '3.3.3.3'
])}}

dnsserver.listen_port = 5053
dnsserver.listen_host = ''
dnsserver.serve()
