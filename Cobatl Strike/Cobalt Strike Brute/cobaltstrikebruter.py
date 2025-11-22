#!/usr/bin/env python3
import time
import socket
import ssl
import argparse
import concurrent.futures
import sys
import re

from urllib.parse import quote
from multiprocessing import Pool, Manager


class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class DisconnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node


class Connector:
    def __init__(self):
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE
        pass

    def is_connected(self):
        return self.sock and self.ssl_sock

    def open(self, hostname, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == socket.gethostname():
            ipaddress = socket.gethostbyname_ex(hostname)[2][0]
            self.ssl_sock.connect((ipaddress, port))
        else:
            self.ssl_sock.connect((hostname, port))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        self.ssl_sock.sendall(buffer)

    def receive(self):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)

        return data_buffer


def passwordcheck(host, port, password):
    if len(password) > 0:
        result = None
        conn = Connector()
        conn.open(host, int(port))
        payload = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(
            bytes(password, "ascii").ljust(256, b"A"))
        conn.send(payload)
        if conn.is_connected(): result = conn.receive()
        if conn.is_connected(): conn.close()
        if result == bytearray(b"\x00\x00\xca\xfe"):
            print(host,password)
            return password
        else:
            return False
    else:
        pass


def forin(ip, port, common_weak_password):
    for password in common_weak_password:
        passwordcheck(ip,port,password)


def test():
    path = 'ip.txt'
    pass_dir = 'wordlist.txt'
    wordlist = open(pass_dir, 'r').read().split('\n')
    p = Pool(300)
    q = Manager().Queue()
    fr = open(path, 'r')
    rtar = fr.readlines()
    fr.close()
    for i in range(len(rtar)):
        ruleip=re.compile('(.*?):')
        try:
            rip =(ruleip.findall(rtar[i]))[0]
        except:
            rip = str(rtar[i]).strip('\n')
        ruleport=re.compile(':(.*)')
        try:
            rport=ruleport.findall(rtar[i])[0]
        except:
            rport='50050'  #默认指定50050端口
        p.apply_async(forin,args=(rip, rport, wordlist))
    p.close()
    p.join()


if __name__ == '__main__':
    test()
