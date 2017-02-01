#!/usr/bin/env python

import socket
import argparse


def run_server(IP, port, bufSize):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, port))
    s.listen(1) # allow one connection
    
    conn, addr = s.accept()
    print 'Connection address:', addr
    while 1:
        data = conn.recv(bufSize)
        if not data: break
    conn.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('IP', type=str, help="the IP address to bind to")
    parser.add_argument('port', type=int, help="the port to start the server on")
    parser.add_argument('bufSize', type=int, help="the server receive buffer size to use")
    args = parser.parse_args()

    run_server(args.IP, args.port, args.bufSize)


if __name__ == "__main__":
    main()

