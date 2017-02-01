#!/usr/bin/env python

import socket
import argparse
from get_ctime import *

def run_client(IP, port, bufSize, startTime):
    MESSAGE = "D"*bufSize
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))

    # keep polling CLOCK_REALTIME until startTime is reached
    wait_until(startTime)

    # send data for 10 seconds 
    t = get_real_time()
    endTime = t + 10
    while t <= endTime:
        s.sendall(MESSAGE)
        t = get_real_time()
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    
def wait_until(startTime):
    currTime = get_real_time()
    while currTime < startTime:
        currTime = get_real_time()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('IP', type=str, help="the IP address to connect to")
    parser.add_argument('port', type=int, help="the port to connect to")
    parser.add_argument('bufSize', type=int, help="the client send buffer size to use")
    parser.add_argument('startTime', type=int, help="the time to start sending data")
    args = parser.parse_args()

    run_client(args.IP, args.port, args.bufSize, args.startTime)


if __name__ == "__main__":
    main()

