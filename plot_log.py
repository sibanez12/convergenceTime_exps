#!/usr/bin/env python

import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import sys, os, re, argparse
from collections import OrderedDict
import re, csv, struct, socket
from scapy_patch import rdpcap_raw
from workload import Workload
from mp_max_min import MPMaxMin

sys.path.append(os.path.expandvars('$P4_PROJECT_DIR/testdata/'))
from perc_headers import PERC_CONTROL, PERC_DATA

flowCtrlTimes = OrderedDict()
flowDataTimes = OrderedDict()
flowSeqNos = OrderedDict()

data_q_sizes = OrderedDict() # indexed by queue number
data_q_sizes[0] = []
data_q_sizes[1] = []
data_q_sizes[2] = []
data_q_sizes[3] = []

ctrl_q_sizes = OrderedDict() # indexed by queue number
ctrl_q_sizes[0] = []
ctrl_q_sizes[1] = []
ctrl_q_sizes[2] = []
ctrl_q_sizes[3] = []

q_size_time = []

flowTimes = OrderedDict()
flowDemands = OrderedDict()
flowAllocs = OrderedDict()
flowLabels = OrderedDict()
flowLinkCaps = OrderedDict()
flowSumSats = OrderedDict()
flowNumFlows = OrderedDict()
flowNumSats = OrderedDict()
flowNewMaxSats = OrderedDict()
flowRs = OrderedDict()

flowAvgTimes = OrderedDict()
flowRates = OrderedDict()

CONVERGENCE_THRESH = 0.40
CONVERGENCE_INTERVAL = 50e-3 # 50 ms

RATE_AVG_INTERVAL = 0.001 # seconds 

LINK_CAP = 2**31

DATA_PKT_SIZE = 1460 # bytes

BASE_PORT = 915
MAX_NUM_FLOWS = 100

MIN_RATE = 0.01 # Gbps

CTime = None
CT_start = None
CT_end = None

"""
Read the pcap trace and get the Perc_control and Perc_data packet info
"""
def read_pcap_pkts(pcap_file):
    pcap_pkts = rdpcap_raw(pcap_file)
    for (pkt, _) in pcap_pkts:
        try:
            etherType = struct.unpack(">H", pkt[12:14])[0] 
            if etherType == PERC_CONTROL:
                flowID = struct.unpack(">I", pkt[14:18])[0]
                demand = struct.unpack(">I", pkt[22:26])[0]
                timestamp = struct.unpack(">Q", pkt[27:35])[0]
                label_0 = struct.unpack(">B", pkt[35])[0]
                alloc_0 = struct.unpack(">I", pkt[38:42])[0]
                linkCap = struct.unpack(">I", pkt[50:54])[0]
                sumSat = struct.unpack(">I", pkt[54:58])[0]
                numFlows = struct.unpack(">I", pkt[58:62])[0]
                numSat = struct.unpack(">I", pkt[62:66])[0]
                maxSat = struct.unpack(">I", pkt[66:70])[0]
                R = struct.unpack(">I", pkt[70:74])[0]
                log_ctrl_pkt(flowID, demand, timestamp, label_0, alloc_0, linkCap, sumSat, numFlows, numSat, maxSat, R)
            elif etherType == PERC_DATA:
                flowID = struct.unpack(">I", pkt[14:18])[0]
                seqNo = struct.unpack(">I", pkt[22:26])[0]
                nf0_data_q_size = struct.unpack("<H", pkt[32:34])[0] 
                nf1_data_q_size = struct.unpack("<H", pkt[34:36])[0] 
                nf2_data_q_size = struct.unpack("<H", pkt[36:38])[0] 
                nf3_data_q_size = struct.unpack("<H", pkt[38:40])[0] 
                nf0_ctrl_q_size = struct.unpack("<H", pkt[40:42])[0] 
                nf1_ctrl_q_size = struct.unpack("<H", pkt[42:44])[0] 
                nf2_ctrl_q_size = struct.unpack("<H", pkt[44:46])[0] 
                nf3_ctrl_q_size = struct.unpack("<H", pkt[46:48])[0]
                timestamp = struct.unpack("<Q", pkt[48:56])[0]
                log_data_pkt(flowID, seqNo, nf0_data_q_size, nf1_data_q_size, nf2_data_q_size, nf3_data_q_size, 
                             nf0_ctrl_q_size, nf1_ctrl_q_size, nf2_ctrl_q_size, nf3_ctrl_q_size, timestamp) 
        except struct.error as e:
            print >> sys.stderr, "WARNING: could not unpack packet to obtain all fields"
            pass

def log_ctrl_pkt(flowID, demand, timestamp, label_0, alloc_0, linkCap, sumSat, numFlows, numSat, maxSat, R):
    if flowID not in flowCtrlTimes.keys():
        flowCtrlTimes[flowID] = [timestamp*5.0]
        flowDemands[flowID] = [(float(demand)/LINK_CAP)*10]
        flowAllocs[flowID] = [(float(alloc_0)/LINK_CAP)*10]
        flowLabels[flowID] = [label_0]
        flowLinkCaps[flowID] = [(float(linkCap)/LINK_CAP)*10]
        flowSumSats[flowID] = [(float(sumSat)/LINK_CAP)*10]
        flowNumFlows[flowID] = [numFlows]
        flowNumSats[flowID] = [numSat]
        flowNewMaxSats[flowID] = [(float(maxSat)/LINK_CAP)*10]
        flowRs[flowID] = [(float(R)/LINK_CAP)*10]
    else:
        flowCtrlTimes[flowID].append(timestamp*5.0)
        flowDemands[flowID].append((float(demand)/LINK_CAP)*10)
        flowAllocs[flowID].append((float(alloc_0)/LINK_CAP)*10)
        flowLabels[flowID].append(label_0)
        flowLinkCaps[flowID].append((float(linkCap)/LINK_CAP)*10)
        flowSumSats[flowID].append((float(sumSat)/LINK_CAP)*10)
        flowNumFlows[flowID].append(numFlows)
        flowNumSats[flowID].append(numSat)
        flowNewMaxSats[flowID].append((float(maxSat)/LINK_CAP)*10)
        flowRs[flowID].append((float(R)/LINK_CAP)*10)

def log_data_pkt(flowID, seqNo, nf0_data_q_size, nf1_data_q_size, nf2_data_q_size, nf3_data_q_size,
                 nf0_ctrl_q_size, nf1_ctrl_q_size, nf2_ctrl_q_size, nf3_ctrl_q_size, timestamp):
    data_q_sizes[0].append(nf0_data_q_size*32.0) # bytes
    data_q_sizes[1].append(nf1_data_q_size*32.0) # bytes
    data_q_sizes[2].append(nf2_data_q_size*32.0) # bytes
    data_q_sizes[3].append(nf3_data_q_size*32.0) # bytes
    ctrl_q_sizes[0].append(nf0_ctrl_q_size*32.0) # bytes
    ctrl_q_sizes[1].append(nf1_ctrl_q_size*32.0) # bytes
    ctrl_q_sizes[2].append(nf2_ctrl_q_size*32.0) # bytes
    ctrl_q_sizes[3].append(nf3_ctrl_q_size*32.0) # bytes
    q_size_time.append(timestamp*5.0)
    if flowID not in flowDataTimes.keys():
        flowDataTimes[flowID] = [timestamp*5.0]
        flowSeqNos[flowID] = [0]
    else:
        flowTimes[flowID].append(timestamp*5.0)
        flowSeqNos[flowID].append(seqNo)

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

def plot_data_q_data(args):
    fig_handle =  plt.figure()

    if (args.nf0_data):
        plt.plot(q_size_time, data_q_sizes[0], label='nf0', marker='o')
    if (args.nf1_data):
        plt.plot(q_size_time, data_q_sizes[1], label='nf1', marker='o')
    if (args.nf2_data):
        plt.plot(q_size_time, data_q_sizes[2], label='nf2', marker='o')
    if (args.nf3_data):
        plt.plot(q_size_time, data_q_sizes[3], label='nf3', marker='o')

    plt.subplots_adjust(right=0.9)    
    plt.legend(bbox_to_anchor=(1.01,1), loc="upper left")
    plt.title('Output Data Queue Sizes over time')
    plt.xlabel('time (ns)')
    plt.ylabel('Queue Size (B)')

def plot_ctrl_q_data(args):
    fig_handle =  plt.figure()

    if (args.nf0_ctrl):
        plt.plot(q_size_time, ctrl_q_sizes[0], label='nf0', marker='o')
    if (args.nf1_ctrl):
        plt.plot(q_size_time, ctrl_q_sizes[1], label='nf1', marker='o')
    if (args.nf2_ctrl):
        plt.plot(q_size_time, ctrl_q_sizes[2], label='nf2', marker='o')
    if (args.nf3_ctrl):
        plt.plot(q_size_time, ctrl_q_sizes[3], label='nf3', marker='o')

    plt.subplots_adjust(right=0.9)    
    plt.legend(bbox_to_anchor=(1.01,1), loc="upper left")
    plt.title('Output Control Queue Sizes over time')
    plt.xlabel('time (ns)')
    plt.ylabel('Queue Size (B)')


def plot_flow_data(time_data, flow_data, title, y_label, y_lim=None):
    global CTime, CT_start, CT_end

    fig_handle =  plt.figure()

    if (CTime is not None):
        title += ' (convergence time = {} ms)'.format(CTime*(10**-6))
 
    # plot the results
    for flowID in flow_data.keys():
        times = time_data[flowID]
        y_vals = flow_data[flowID]
        plt.plot(times, y_vals, label='flow {}'.format(flowID), marker='o')

    if (CT_start is not None and CT_end is not None):
        plt.axvline(x=CT_start, color='r', linestyle='--')
        plt.axvline(x=CT_end, color='r', linestyle='--')

    plt.subplots_adjust(right=0.7)    
    plt.legend(bbox_to_anchor=(1.01,1), loc="upper left")
    plt.title(title)
    plt.xlabel('time (ns)')
    plt.ylabel(y_label)
    if y_lim is not None:
        axes = plt.gca()
        axes.set_ylim(y_lim)

def make_plots(args=None):
    if (args.demand or args.all):
        plot_flow_data(flowCtrlTimes, flowDemands, 'Flow demands over time', 'rate (Gbps)', y_lim=[0,11])
    if (args.alloc or args.all):
        plot_flow_data(flowCtrlTimes, flowAllocs, 'Flow allocations over time', 'rate (Gbps)')
    if (args.label or args.all):
        plot_flow_data(flowCtrlTimes, flowLabels, 'Flow labels over time', 'label', y_lim=[0,3])
    if (args.linkCap or args.all):
        plot_flow_data(flowCtrlTimes, flowLinkCaps, 'Flow linkCap measurements over time', 'rate (Gbps)', y_lim=[0,11])
    if (args.sumSat or args.all):
        plot_flow_data(flowCtrlTimes, flowSumSats, 'Flow sumSat state over time', 'rate (Gbps)', y_lim=[0,11])
    if (args.numFlows or args.all):
        plot_flow_data(flowCtrlTimes, flowNumFlows, 'Flow numFlows state over time', 'numFlows')
    if (args.numSat or args.all):
        plot_flow_data(flowCtrlTimes, flowNumSats, 'Flow numSat state over time', 'numSat')
    if (args.maxSat or args.all):
        plot_flow_data(flowCtrlTimes, flowNewMaxSats, 'Flow maxSat state over time', 'rate (Gbps)', y_lim=[0,11])
    if (args.R or args.all):
        plot_flow_data(flowCtrlTimes, flowRs, 'Flow R measurements over time', 'rate (Gbps)', y_lim=[0,11])
    if (args.nf0_data or args.nf1_data or args.nf2_data or args.nf3_data):
        plot_data_q_data(args)
    if (args.nf0_ctrl or args.nf1_ctrl or args.nf2_ctrl or args.nf3_ctrl):
        plot_ctrl_q_data(args)    

    font = {'family' : 'normal',
            'weight' : 'bold',
            'size'   : 22}
    matplotlib.rc('font', **font)

    plt.show()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('logged_pkts', type=str, help="the pcap file that contains all of the logged control packets from the switch")
    parser.add_argument('--all', action='store_true', default=False, help='plot all the info about the flows')
    parser.add_argument('--demand', action='store_true', default=False, help='plot the demands of each flow')
    parser.add_argument('--alloc', action='store_true', default=False, help='plot the allocation of each flow')
    parser.add_argument('--label', action='store_true', default=False, help='plot the label of each flow')
    parser.add_argument('--linkCap', action='store_true', default=False, help='plot the linkCap in each pkt')
    parser.add_argument('--sumSat', action='store_true', default=False, help='plot the sumSat of each flow')
    parser.add_argument('--numFlows', action='store_true', default=False, help='plot the numFlows of each flow')
    parser.add_argument('--numSat', action='store_true', default=False, help='plot the numSat of each flow')
    parser.add_argument('--maxSat', action='store_true', default=False, help='plot the newMaxSat of each flow')
    parser.add_argument('--R', action='store_true', default=False, help='plot the R of each flow')
    parser.add_argument('--nf0_data', action='store_true', default=False, help='plot size of nf0 output data queue over time')
    parser.add_argument('--nf1_data', action='store_true', default=False, help='plot size of nf1 output data queue over time')
    parser.add_argument('--nf2_data', action='store_true', default=False, help='plot size of nf2 output data queue over time')
    parser.add_argument('--nf3_data', action='store_true', default=False, help='plot size of nf3 output data queue over time')
    parser.add_argument('--nf0_ctrl', action='store_true', default=False, help='plot size of nf0 output ctrl queue over time')
    parser.add_argument('--nf1_ctrl', action='store_true', default=False, help='plot size of nf1 output ctrl queue over time')
    parser.add_argument('--nf2_ctrl', action='store_true', default=False, help='plot size of nf2 output ctrl queue over time')
    parser.add_argument('--nf3_ctrl', action='store_true', default=False, help='plot size of nf3 output ctrl queue over time')
    parser.add_argument('--rtt', action='store_true', default=False, help='report the average rtt')
    parser.add_argument('--workload', type=str, default="", help="the file that specifies the workload that was run to produce these results")
    args = parser.parse_args()

    read_pcap_pkts(args.logged_pkts)
#    calc_flow_stats()
    if (args.workload != ""):
        log_CT(args.workload) 
    make_plots(args=args)


if __name__ == "__main__":
    main()
