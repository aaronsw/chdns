#!/usr/bin/python

"""
Simple Python DNS server.
Originally from https://code.google.com/p/pymds/ by Tom Pinckney.
"""
__license__ = "BSD"

import sys
import socket
import struct
import ConfigParser
import signal
import getopt
import traceback

from dnsutils import *

class DnsError(Exception):
    pass

def serve():
    print 'x'
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind((listen_host, listen_port))
    #ns_resource_records, ar_resource_records = compute_name_server_resources(_name_servers)
    ns_resource_records = ar_resource_records = []
    while True:
        try:
            req_pkt, src_addr = udps.recvfrom(512)   # max UDP DNS pkt size
        except socket.error:
            continue
        qid = None
        print 'a'
        try:
            exception_rcode = None
            try:
                qid, question, qtype, qclass = parse_request(req_pkt)
            except:
                exception_rcode = 1
                raise Exception("could not parse query")
            question = map(lambda x: x.lower(), question)
            print question
            found = False
            for config in config_files.values():
                if question[1:] == config['domain']:
                    query = question[0]
                elif question == config['domain']:
                    query = ''
                else:
                    continue
                rcode, an_resource_records = config['source'].get_response(query, config['domain'], qtype, qclass, src_addr)
                if rcode == 0 and 'filters' in config:
                    for f in config['filters']:
                        an_resource_records = f.filter(query, config['domain'], qtype, qclass, src_addr, an_resource_records)
                resp_pkt = format_response(qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records)
                found = True
                break
            if not found:
                exception_rcode = 3
                raise Exception("query is not for our domain: %s" % ".".join(question))
        except:
            traceback.print_exc()
            if qid:
                if exception_rcode is None:
                    exception_rcode = 2
                resp_pkt = format_response(qid, question, qtype, qclass, exception_rcode, [], [], [])
            else:
                continue
        udps.sendto(resp_pkt, src_addr)

def compute_name_server_resources(name_servers):
    ns = []
    ar = []
    for name_server, ip, ttl in name_servers:
        ns.append({'qtype':2, 'qclass':1, 'ttl':ttl, 'rdata':labels2str(name_server)})
        ar.append({'qtype':1, 'qclass':1, 'ttl':ttl, 'rdata':struct.pack("!I", ip)})
    return ns, ar
        
def parse_request(packet):
    hdr_len = 12
    header = packet[:hdr_len]
    qid, flags, qdcount, _, _, _ = struct.unpack('!HHHHHH', header)
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xf
    rd = (flags >> 8) & 0x1
    #print "qid", qid, "qdcount", qdcount, "qr", qr, "opcode", opcode, "rd", rd
    if qr != 0 or opcode != 0 or qdcount == 0:
        raise DnsError("Invalid query")
    body = packet[hdr_len:]
    labels = []
    offset = 0
    while True:
        label_len, = struct.unpack('!B', body[offset:offset+1])
        offset += 1
        if label_len & 0xc0:
            raise DnsError("Invalid label length %d" % label_len)
        if label_len == 0:
            break
        label = body[offset:offset+label_len]
        offset += label_len
        labels.append(label)
    qtype, qclass= struct.unpack("!HH", body[offset:offset+4])
    if qclass != 1:
        raise DnsError("Invalid class: " + qclass)
    return (qid, labels, qtype, qclass)

def format_response(qid, question, qtype, qclass, rcode, an_resource_records, ns_resource_records, ar_resource_records):
    resources = []
    resources.extend(an_resource_records)
    num_an_resources = len(an_resource_records)
    num_ns_resources = num_ar_resources = 0
    if rcode == 0:
        resources.extend(ns_resource_records)
        resources.extend(ar_resource_records)
        num_ns_resources = len(ns_resource_records)
        num_ar_resources = len(ar_resource_records)
    pkt = format_header(qid, rcode, num_an_resources, num_ns_resources, num_ar_resources)
    pkt += format_question(question, qtype, qclass)
    for resource in resources:
        pkt += format_resource(resource, question)
    return pkt

def format_header(qid, rcode, ancount, nscount, arcount):
    flags = 0
    flags |= (1 << 15)
    flags |= (1 << 10)
    flags |= (rcode & 0xf)
    hdr = struct.pack("!HHHHHH", qid, flags, 1, ancount, nscount, arcount)
    return hdr

def format_question(question, qtype, qclass):
    q = labels2str(question)
    q += struct.pack("!HH", qtype, qclass)
    return q

def format_resource(resource, question):
    r = ''
    r += labels2str(question)
    r += struct.pack("!HHIH", resource['qtype'], resource['qclass'], resource['ttl'], len(resource['rdata']))
    r += resource['rdata']
    return r
    
def die(msg):
    sys.stderr.write(msg)
    sys.exit(-1)
