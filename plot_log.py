#!/usr/bin/env python

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import sys, os, re, argparse
from collections import OrderedDict
import pandas, re, csv, struct, socket
from scapy_patch import rdpcap_raw

flowTimes = OrderedDict()
flowSeqNos = OrderedDict()
flowPktSizes = OrderedDict()

flowAvgTimes = OrderedDict()
flowRates = OrderedDict()
flowGoodputs = OrderedDict()

initSeqNos = OrderedDict()

RATE_AVG_INTERVAL = 0.001 # seconds 
HEADER_SIZE = 40 # bytes, IP + TCP header size

"""
Write the data from the pkts into a csv so we don't have to
read the pcap trace again. The csv file will be written into
the same directory as the pcap trace.
"""
def read_pcap_pkts(pcap_file):
    outDir = os.path.dirname(pcap_file)
    out_file = pcap_file.replace('.pcap', '.csv')
    pcap_pkts = rdpcap_raw(pcap_file)
    with open(out_file, 'w') as f:
        for (pkt, _) in pcap_pkts:
            try:
                ip_len = struct.unpack(">H", pkt[16:18])[0]
                proto = struct.unpack(">B", pkt[23])[0]
                src_ip = socket.inet_ntoa(pkt[26:30])
                dst_ip = socket.inet_ntoa(pkt[30:34])
                src_port = struct.unpack(">H", pkt[34:36])[0]
                dst_port = struct.unpack(">H", pkt[36:38])[0]
                seqNo = struct.unpack(">L", pkt[38:42])[0]
                timestamp = struct.unpack(">Q", pkt[54:62])[0]
                f.write ('{},{},{},{},{},{},{},{}\n'.format(ip_len, proto, src_ip, dst_ip, src_port, dst_port, seqNo, timestamp))
                log_pkt(ip_len, proto, src_ip, dst_ip, src_port, dst_port, seqNo, timestamp) 
            except struct.error as e:
                print >> sys.stderr, "WARNING: could not unpack packet to obtain all fields"

def read_csv_pkts(csv_file):
    with open(csv_file, 'rb') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            log_pkt(int(row[0]), int(row[1]), row[2], row[3], int(row[4]), int(row[5]), int(row[6]), int(row[7]))

def log_pkt(ip_len, proto, src_ip, dst_ip, src_port, dst_port, seqNo, timestamp):
    flowID = (src_ip, dst_ip, proto, src_port, dst_port)
    if flowID not in flowTimes.keys():
        initSeqNos[flowID] = seqNo
        flowTimes[flowID] = [timestamp*5.0]
        flowSeqNos[flowID] = [0]
        flowPktSizes[flowID] = [ip_len - HEADER_SIZE]
    else:
        flowTimes[flowID].append(timestamp*5.0)
        flowSeqNos[flowID].append(seqNo - initSeqNos[flowID])
        flowPktSizes[flowID].append(ip_len - HEADER_SIZE)

#def get_flow_info(log_file):
#    logged_pkts = rdpcap(log_file)
#    for pkt in logged_pkts:
#        if TCP in pkt:
#            flowID = (pkt[IP].src, pkt[IP].dst, pkt[IP].proto, pkt.sport, pkt.dport) # flowID = 5-tuple 
#            if flowID not in flowTimes.keys():
#                initSeqNos[flowID] = pkt.seq
#                try:
#                    timestamp = struct.unpack(">Q", pkt.load[0:8])[0]
#                    flowTimes[flowID] = [timestamp*5.0]
#                    flowSeqNos[flowID] = [0]
#                    flowPktSizes[flowID] = [pkt[IP].len - HEADER_SIZE]
#                except struct.error as e:
#                    print "ERROR: could not unpack load: ", pkt.load[0:8]
#            else:
#                try:
#                    timestamp = struct.unpack(">Q", pkt.load[0:8])[0]
#                    flowTimes[flowID].append(timestamp*5.0)
#                    flowSeqNos[flowID].append(pkt.seq - initSeqNos[flowID])
#                    flowPktSizes[flowID].append(pkt[IP].len - HEADER_SIZE)
#                except struct.error as e:
#                    print "ERROR: could not unpack load: ", pkt.load[0:8]                

def calc_flow_stats():
    for flowID in flowTimes.keys():
        (time_vals, rate_vals, goodput_vals, num_retrans) = process_flow(flowTimes[flowID], flowPktSizes[flowID], flowSeqNos[flowID]) 
        flowAvgTimes[flowID] = time_vals
        flowRates[flowID] = rate_vals
        flowGoodputs[flowID] = goodput_vals
        print "flow: ", str(flowID), " num_retransmissions = ", num_retrans 

def process_flow(times, pktSizes, seqNos):
    rate_vals = []
    goodput_vals = []
    time_vals = []
    prev_time = times[0]
    byte_cnt = 0
    new_byte_cnt = 0
    max_seqNo = seqNos[0]
    num_retrans = 0
    for (cur_time, pktSize, seqNo) in zip(times, pktSizes, seqNos):
        if cur_time <= prev_time + RATE_AVG_INTERVAL*1e9:
            # increment
            byte_cnt += pktSize
            if (seqNo > max_seqNo):
                max_seqNo = seqNo
                new_byte_cnt += pktSize
            else:
                num_retrans += 1
        else:
            # update
            interval = cur_time - prev_time # ns
            rate = (byte_cnt*8.0)/float(interval)  # Gb/s
            goodput = (new_byte_cnt*8.0)/float(interval) # Gb/s
            avg_time = (cur_time + prev_time)/2.0
            rate_vals.append(rate)
            goodput_vals.append(goodput)
            time_vals.append(avg_time)
            # reset
            prev_time = cur_time
            byte_cnt = 0
            new_byte_cnt = 0
    return (time_vals, rate_vals, goodput_vals, num_retrans)


def dump_flow_info():
     # plot the results
    for flowID in flowRates.keys():
        times = flowTimes[flowID]
        demands = flowDemands[flowID]
        allocs = flowAllocs[flowID]
        labels = flowLabels[flowID]
        with open('flow_{}_rate.csv'.format(flowID), 'wb') as csvfile:
            wr = csv.writer(csvfile)
            wr.writerow(times)
            wr.writerow(demands)
            wr.writerow(allocs)
            wr.writerow(labels)

def plot_flow_data(time_data, flow_data, title, y_label, y_lim=None):
    fig_handle =  plt.figure()
    
    # plot the results
    for flowID in flow_data.keys():
        times = time_data[flowID]
        y_vals = flow_data[flowID]
        plt.plot(times, y_vals, label='flow {0}'.format(flowID), marker='o')
    
    plt.legend()
    plt.title(title)
    plt.xlabel('time (ns)')
    plt.ylabel(y_label)
    if y_lim is not None:
        axes = plt.gca()
        axes.set_ylim(y_lim)
#    plt.show()

def make_plots(seq, rate, goodput):
    calc_flow_stats()
    if (seq):
        plot_flow_data(flowTimes, flowSeqNos, 'Flow Sequence Numbers over time', 'SeqNo')
    if (rate):
        plot_flow_data(flowAvgTimes, flowRates, 'Avg Flow Rates (avg interval = {} sec)'.format(RATE_AVG_INTERVAL), 'Rate (Gbps)')
    if (goodput):
        plot_flow_data(flowAvgTimes, flowGoodputs, 'Avg Goodputs (avg interval = {} sec)'.format(RATE_AVG_INTERVAL), 'Goodput (Gbps)')

    font = {'family' : 'normal',
            'weight' : 'bold',
            'size'   : 22}
    matplotlib.rc('font', **font)

    plt.show()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seq', action='store_true', default=False, help='plot the seqNos of each flow')
    parser.add_argument('--rate', action='store_true', default=False, help='plot the avg rate of each flow')
    parser.add_argument('--goodput', action='store_true', default=False, help='plot the avg goodput of each flow')
    parser.add_argument('logged_pkts', type=str, help="the pcap file that contains all of the logged control packets from the switch")
    args = parser.parse_args()

    if (args.logged_pkts.endswith('.pcap')):
        read_pcap_pkts(args.logged_pkts)
    elif (args.logged_pkts.endswith('.csv')):
        read_csv_pkts(args.logged_pkts)
    else:
        print >> sys.stderr, "ERROR: unrecognized input file type"
        sys.exit(1)

    make_plots(args.seq, args.rate, args.goodput)


if __name__ == "__main__":
    main()
