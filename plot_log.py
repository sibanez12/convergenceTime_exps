#!/usr/bin/env python

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import sys, os, re, argparse
from collections import OrderedDict
import pandas, re, csv, struct, socket
from scapy_patch import rdpcap_raw
from workload import Workload
from mp_max_min import MPMaxMin

flowTimes = OrderedDict()
flowSeqNos = OrderedDict()
flowPktSizes = OrderedDict()

flowAvgTimes = OrderedDict()
flowRates = OrderedDict()
flowGoodputs = OrderedDict()

initSeqNos = OrderedDict()

CONVERGENCE_THRESH = 0.40
CONVERGENCE_INTERVAL = 50e-3 # 50 ms

RATE_AVG_INTERVAL = 0.001 # seconds 
HEADER_SIZE = 40 # bytes, IP + TCP header size
TCP_PROTO = 6

BASE_PORT = 915
MAX_NUM_FLOWS = 100

MIN_RATE = 0.01 # Gbps

CTime = None
CT_start = None
CT_end = None

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
                if proto == TCP_PROTO:
                    log_pkt(ip_len, proto, src_ip, dst_ip, src_port, dst_port, seqNo, timestamp) 
            except struct.error as e:
#                print >> sys.stderr, "WARNING: could not unpack packet to obtain all fields"
                pass

def read_csv_pkts(csv_file):
    with open(csv_file, 'rb') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            log_pkt(int(row[0]), int(row[1]), row[2], row[3], int(row[4]), int(row[5]), int(row[6]), int(row[7]))

def log_pkt(ip_len, proto, src_ip, dst_ip, src_port, dst_port, seqNo, timestamp):
    flowID = (src_ip, dst_ip, proto, src_port, dst_port)
    if dst_port >= BASE_PORT and dst_port <= BASE_PORT + MAX_NUM_FLOWS:
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
        results = process_flow(flowTimes[flowID], flowPktSizes[flowID], flowSeqNos[flowID])
        if results is not None:
            (time_vals, rate_vals, goodput_vals, num_retrans) = results 
            flowAvgTimes[flowID] = time_vals
            flowRates[flowID] = rate_vals
            flowGoodputs[flowID] = goodput_vals
            print "flow: ", str(flowID), " num_retransmissions = ", num_retrans 
        else:
            del flowTimes[flowID]
            del flowSeqNos[flowID]
            del flowPktSizes[flowID]

def process_flow(times, pktSizes, seqNos):
    rate_vals = []
    goodput_vals = []
    time_vals = []
    prev_time = times[0]
    byte_cnt = 0
    new_byte_cnt = 0
    max_seqNo = seqNos[0]
    num_retrans = 0
    max_rate = 0
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
            max_rate = rate if (rate > max_rate) else max_rate
            goodput = (new_byte_cnt*8.0)/float(interval) # Gb/s
            avg_time = (cur_time + prev_time)/2.0
            rate_vals.append(rate)
            goodput_vals.append(goodput)
            time_vals.append(avg_time)
            # reset
            prev_time = cur_time
            byte_cnt = 0
            new_byte_cnt = 0
    # ensure the flows max rate exceeds the minimum threshold to avoid looking at the
    # pre-connection iperf3 flow
    if max_rate > MIN_RATE:
        return (time_vals, rate_vals, goodput_vals, num_retrans)
    else:
        return None


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

def log_CT(workload_file):
    global CTime, CT_start, CT_end
    result = compute_CT(workload_file)

    if result is None:
        print "Failed to converge"
    else:
        (CTime, CT_start, CT_end) = result
        print "Convergence Time = {} ms".format(CTime*(10**-6)) 

"""
Calculate the time it takes for ALL flows to be within 40% of their
ideal rates for 50 consecutive milliseconds.
"""
def compute_CT(workload_file):
    workload = Workload(workload_file)
    wf = MPMaxMin(workload)
    idealRates = wf.maxmin_x

    # find the time of the last flow change
    start_time = max([time[0] for time in flowAvgTimes.values()])
    cnv_win_start_vals = get_flow_start_times()
    cnv_win_end_vals = get_flow_start_times()
    last_sample_ct = init_last_samples() # dict to keep track of whether or not the last sample of this flow was in the correct range
    rate_list = make_rate_list()
    for point in rate_list:        
        (t, r, flow_num) = point
        idealRate = idealRates[flow_num]
        if (r >= (1-CONVERGENCE_THRESH)*idealRate and r <= (1+CONVERGENCE_THRESH)*idealRate):
            if (last_sample_ct[flow_num] == False):
                cnv_win_start_vals[flow_num] = t
            cnv_win_end_vals[flow_num] = t
            hasConverged = check_convergence(cnv_win_start_vals, cnv_win_end_vals)
            last_sample_ct[flow_num] = True
            if hasConverged:
                ct_start_time = max(cnv_win_start_vals.values())
                ct_end_time = t
                convergence_time = ct_start_time - start_time
                return (convergence_time, ct_start_time, ct_end_time)
        else:
            cnv_win_start_vals[flow_num] = t
            last_sample_ct[flow_num] = False
    return None # failed to converge

"""
Checks if the difference between the end and start of each window exceeds the CONVERGENCE_INTERVAL
"""
def check_convergence(cnv_win_start_vals, cnv_win_end_vals):
    for flow_num in cnv_win_start_vals.keys():
         if (cnv_win_end_vals[flow_num] - cnv_win_start_vals[flow_num] < CONVERGENCE_INTERVAL*(10**9)):
             return False
    return True


def init_last_samples():
    last_sample_ct = {}
    for flow_tuple in flowRates.keys():
        flow_num = flow_tuple[4] - BASE_PORT
        last_sample_ct[flow_num] = False
    return last_sample_ct

"""
Creates a list of rate measurements with the form:
(time, rate, flow_num)
The points are sorted by the time value
"""                
def make_rate_list():
    rate_list = []
    for flow_tuple in flowRates.keys():
        flow_num = flow_tuple[4] - BASE_PORT
        rate_list += zip(flowAvgTimes[flow_tuple], flowRates[flow_tuple], [flow_num]*len(flowRates[flow_tuple]))
    # combine lists stored in rate_points dict and sort by the first element of each point
    rate_list.sort(key=lambda x: x[0])
    return rate_list

 
def get_flow_start_times():
    start_times = {}
    for flow_tuple in flowAvgTimes.keys():
        dst_port = flow_tuple[4]
        flow_num = dst_port - BASE_PORT
        start_times[flow_num] = flowAvgTimes[flow_tuple][0]
    return start_times

def get_rate_samples(index):
    time_samps = {}
    rate_samps = {}
    for flow_tuple in flowAvgTimes.keys():
        if index >= len(flowAvgTimes[flow_tuple]):
            return None, None
        else:
            dst_port = flow_tuple[4]
            flow_num = dst_port - BASE_PORT
            time_samps[flow_num] = flowAvgTimes[flow_tuple][index]
            rate_samps[flow_num] = flowRates[flow_tuple][index]
    return (time_samps, rate_samps)

def plot_flow_data(time_data, flow_data, title, y_label, y_lim=None):
    global CTime, CT_start, CT_end

    fig_handle =  plt.figure()

    if (CTime is not None):
        title += ' (convergence time = {} ms)'.format(CTime*(10**-6))
 
    # plot the results
    for flowID in flow_data.keys():
        times = time_data[flowID]
        y_vals = flow_data[flowID]
        plt.plot(times, y_vals, label='flow {0}'.format(flowID), marker='o')

    if (CT_start is not None and CT_end is not None):
        plt.axvline(x=CT_start, color='r', linestyle='--')
        plt.axvline(x=CT_end, color='r', linestyle='--')
    
    plt.legend()
    plt.title(title)
    plt.xlabel('time (ns)')
    plt.ylabel(y_label)
    if y_lim is not None:
        axes = plt.gca()
        axes.set_ylim(y_lim)

def make_plots(seq, rate, goodput):
    if (seq):
        print "plotting SeqNos..."
        plot_flow_data(flowTimes, flowSeqNos, 'Flow Sequence Numbers over time', 'SeqNo')
    if (rate):
        print "plotting Rates..."
        plot_flow_data(flowAvgTimes, flowRates, 'Avg Flow Rates (avg interval = {} sec)'.format(RATE_AVG_INTERVAL), 'Rate (Gbps)')
    if (goodput):
        print "plotting Goodputs..."
        plot_flow_data(flowAvgTimes, flowGoodputs, 'Avg Goodputs (avg interval = {} sec)'.format(RATE_AVG_INTERVAL), 'Goodput (Gbps)')

    font = {'family' : 'normal',
            'weight' : 'bold',
            'size'   : 22}
    matplotlib.rc('font', **font)

    print "showing plots..."
    plt.show()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seq', action='store_true', default=False, help='plot the seqNos of each flow')
    parser.add_argument('--rate', action='store_true', default=False, help='plot the avg rate of each flow')
    parser.add_argument('--goodput', action='store_true', default=False, help='plot the avg goodput of each flow')
    parser.add_argument('--workload', type=str, default="", help="the file that specifies the workload that was run to produce these results")
    parser.add_argument('logged_pkts', type=str, help="the pcap file that contains all of the logged control packets from the switch")
    args = parser.parse_args()

    if (args.logged_pkts.endswith('.pcap')):
        read_pcap_pkts(args.logged_pkts)
    elif (args.logged_pkts.endswith('.csv')):
        read_csv_pkts(args.logged_pkts)
    else:
        print >> sys.stderr, "ERROR: unrecognized input file type"
        sys.exit(1)

    calc_flow_stats()
    if (args.workload != ""):
        log_CT(args.workload) 
    make_plots(args.seq, args.rate, args.goodput)


if __name__ == "__main__":
    main()