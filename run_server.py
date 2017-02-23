#!/usr/bin/env python

import socket
import argparse


def run_server(IP, port, msgLen):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((IP, port))
    s.listen(1) # allow one connection
    
    conn, addr = s.accept()
    print 'Connection address:', addr
    while 1:
        data = conn.recv(msgLen)
        if not data: break
    conn.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('IP', type=str, help="the IP address to bind to")
    parser.add_argument('port', type=int, help="the port to start the server on")
    parser.add_argument('msgLen', type=int, help="the max length of the msgs to receive")
    args = parser.parse_args()

    run_server(args.IP, args.port, args.msgLen)


if __name__ == "__main__":
    main()

