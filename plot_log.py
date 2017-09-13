#!/usr/bin/env python

import numpy as np
import matplotlib
import matplotlib.pyplot as plt, mpld3
from matplotlib.backends.backend_pdf import PdfPages
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

flowDemands = OrderedDict()
flowAllocs = OrderedDict()
flowAllocs[0] = OrderedDict()
flowAllocs[1] = OrderedDict()
flowAllocs[2] = OrderedDict()
flowLabels = OrderedDict()
flowLabels[0] = OrderedDict()
flowLabels[1] = OrderedDict()
flowLabels[2] = OrderedDict()
flowLinkCaps = OrderedDict()
flowSumSats = OrderedDict()
flowNumFlows = OrderedDict()
flowNumSats = OrderedDict()
flowNewMaxSats = OrderedDict()
flowRs = OrderedDict()

flowAvgTimes = OrderedDict()
flowRates = OrderedDict()

OUT_DIR = ""

CONVERGENCE_THRESH = 0.40
CONVERGENCE_INTERVAL = 50e-3 # 50 ms

RATE_AVG_INTERVAL = 0.001 # seconds 

LINK_CAP = 2**31

DATA_PKT_SIZE = 1460 # bytes

BASE_PORT = 915
MAX_NUM_FLOWS = 100

MAX_RATE = 8 # Gbps
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
                label_1 = struct.unpack(">B", pkt[36])[0]
                label_2 = struct.unpack(">B", pkt[37])[0]
                alloc_0 = struct.unpack(">I", pkt[38:42])[0]
                alloc_1 = struct.unpack(">I", pkt[42:46])[0]
                alloc_2 = struct.unpack(">I", pkt[46:50])[0]
                linkCap = struct.unpack(">I", pkt[50:54])[0]
                sumSat = struct.unpack(">I", pkt[54:58])[0]
                numFlows = struct.unpack(">I", pkt[58:62])[0]
                numSat = struct.unpack(">I", pkt[62:66])[0]
                maxSat = struct.unpack(">I", pkt[66:70])[0]
                R = struct.unpack(">I", pkt[70:74])[0]
                log_ctrl_pkt(flowID, demand, timestamp, label_0, label_1, label_2, alloc_0, alloc_1, alloc_2, linkCap, sumSat, numFlows, numSat, maxSat, R)
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

def log_ctrl_pkt(flowID, demand, timestamp, label_0, label_1, label_2, alloc_0, alloc_1, alloc_2, linkCap, sumSat, numFlows, numSat, maxSat, R):
    if flowID not in flowCtrlTimes.keys():
        flowCtrlTimes[flowID] = [timestamp*5.0]
        flowDemands[flowID] = [(float(demand)/LINK_CAP)*MAX_RATE]
        flowAllocs[0][flowID] = [(float(alloc_0)/LINK_CAP)*MAX_RATE]
        flowAllocs[1][flowID] = [(float(alloc_1)/LINK_CAP)*MAX_RATE]
        flowAllocs[2][flowID] = [(float(alloc_2)/LINK_CAP)*MAX_RATE]
        flowLabels[0][flowID] = [label_0]
        flowLabels[1][flowID] = [label_1]
        flowLabels[2][flowID] = [label_2]
        flowLinkCaps[flowID] = [(float(linkCap)/LINK_CAP)*MAX_RATE]
        flowSumSats[flowID] = [(float(sumSat)/LINK_CAP)*MAX_RATE]
        flowNumFlows[flowID] = [numFlows]
        flowNumSats[flowID] = [numSat]
        flowNewMaxSats[flowID] = [(float(maxSat)/LINK_CAP)*MAX_RATE]
        flowRs[flowID] = [(float(R)/LINK_CAP)*MAX_RATE]
    else:
        flowCtrlTimes[flowID].append(timestamp*5.0)
        flowDemands[flowID].append((float(demand)/LINK_CAP)*MAX_RATE)
        flowAllocs[0][flowID].append((float(alloc_0)/LINK_CAP)*MAX_RATE)
        flowAllocs[1][flowID].append((float(alloc_1)/LINK_CAP)*MAX_RATE)
        flowAllocs[2][flowID].append((float(alloc_2)/LINK_CAP)*MAX_RATE)
        flowLabels[0][flowID].append(label_0)
        flowLabels[1][flowID].append(label_0)
        flowLabels[2][flowID].append(label_0)
        flowLinkCaps[flowID].append((float(linkCap)/LINK_CAP)*MAX_RATE)
        flowSumSats[flowID].append((float(sumSat)/LINK_CAP)*MAX_RATE)
        flowNumFlows[flowID].append(numFlows)
        flowNumSats[flowID].append(numSat)
        flowNewMaxSats[flowID].append((float(maxSat)/LINK_CAP)*MAX_RATE)
        flowRs[flowID].append((float(R)/LINK_CAP)*MAX_RATE)

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
        flowDataTimes[flowID].append(timestamp*5.0)
        flowSeqNos[flowID].append(seqNo)

def report_rtt():
    fig_handle =  plt.figure()
    for flowID, times in flowCtrlTimes.items():
        diff = [j-i for i, j in zip(times[:-1], times[1:])]
        avg_diff = np.mean(diff)
        avg_rtt = 2.0*avg_diff
        max_diff = max(diff)
        min_diff = min(diff)
        print "flow {}:".format(flowID)
        print "\tavg_rtt = ", avg_rtt , " (ns)"
        print "\tmax_diff = ", max_diff, " (ns)"
        print "\tmin_diff = ", min_diff, " (ns)"
        print "\tavg_diff = ", avg_diff, " (ns)"
        plot_cdf(diff, 'CDF of time diff between ctrl pkts', 'time (ns)', 'CDF', 'flow {}'.format(flowID))

    axes = plt.gca()
    axes.set_ylim([0,1.2])

def plot_cdf(data, title, xlabel, ylabel, label):
    sortData = np.sort(data)
    yvals = np.arange(len(sortData))/float(len(sortData))
    plt.plot(sortData, yvals, label=label, marker='o')

    plt.subplots_adjust(right=0.9)
    plt.legend(bbox_to_anchor=(1.01,1), loc="upper left")
    plt.ylabel(ylabel)
    plt.xlabel(xlabel)
    plt.title(title)
    plt.grid()

def calc_flow_stats():
    for flowID in flowDataTimes.keys():
        results = process_flow(flowDataTimes[flowID], flowSeqNos[flowID])
        if results is not None:
            (time_vals, rate_vals, num_retrans) = results 
            flowAvgTimes[flowID] = time_vals
            flowRates[flowID] = rate_vals
            print "flow: ", str(flowID), " num_retransmissions = ", num_retrans 
        else:
            del flowDataTimes[flowID]
            del flowSeqNos[flowID]

def process_flow(times, seqNos):
    rate_vals = []
    time_vals = []
    prev_time = times[0]
    byte_cnt = 0
    new_byte_cnt = 0
    max_seqNo = seqNos[0]
    num_retrans = 0
    max_rate = 0
    for (cur_time, seqNo) in zip(times, seqNos):
        if cur_time <= prev_time + RATE_AVG_INTERVAL*1e9:
            # increment
            byte_cnt += DATA_PKT_SIZE
            if (seqNo <= max_seqNo):
                num_retrans += 1
        else:
            # update
            interval = cur_time - prev_time # ns
            rate = (byte_cnt*8.0)/float(interval)  # Gb/s
            max_rate = rate if (rate > max_rate) else max_rate
            avg_time = (cur_time + prev_time)/2.0
            rate_vals.append(rate)
            time_vals.append(avg_time)
            # reset
            prev_time = cur_time
            byte_cnt = 0
            new_byte_cnt = 0
    # ensure the flows max rate exceeds the minimum threshold to avoid looking at the
    # pre-connection iperf3 flow
    if max_rate > MIN_RATE:
        return (time_vals, rate_vals, num_retrans)
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


def plot_flow_data(time_data, flow_data, title, y_label, filename, y_lim=None):
    global CTime, CT_start, CT_end

    fig_handle =  plt.figure()

    if (CTime is not None):
        title += ' (convergence time = {} ms)'.format(CTime*(10**-6))
 
    # plot the results
    for flowID in flow_data.keys():
        times = time_data[flowID]
        y_vals = flow_data[flowID]
        plt.plot(times, y_vals, label='flow {}'.format(flowID)) #, marker='o')

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

    global OUT_DIR
    if OUT_DIR != "":
        save_plot(filename, OUT_DIR)

def save_plot(filename, out_dir):
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    plot_filename = os.path.join(out_dir, filename + '.pdf')

#    fig = plt.gcf()
#    mpld3.save_html(fig, plot_filename)

    pp = PdfPages(plot_filename)
    pp.savefig()
    pp.close()
    print "Saved plot: ", plot_filename

def make_plots(args=None):
    if (args.demand or args.all):
        plot_flow_data(flowCtrlTimes, flowDemands, 'Flow demands over time', 'rate (Gbps)', 'demands', y_lim=[0,MAX_RATE+1])
    if (args.alloc_0 or args.all):
        plot_flow_data(flowCtrlTimes, flowAllocs[0], 'Flow allocations at first hop over time', 'rate (Gbps)', 'alloc_0')
    if (args.alloc_1 or args.all):
        plot_flow_data(flowCtrlTimes, flowAllocs[1], 'Flow allocations at second hop over time', 'rate (Gbps)', 'alloc_1')
    if (args.alloc_2 or args.all):
        plot_flow_data(flowCtrlTimes, flowAllocs[2], 'Flow allocations at third hop over time', 'rate (Gbps)', 'alloc_2')
    if (args.label_0 or args.all):
        plot_flow_data(flowCtrlTimes, flowLabels[0], 'Flow labels at first hop over time', 'label', 'label_0', y_lim=[0,3])
    if (args.label_1 or args.all):
        plot_flow_data(flowCtrlTimes, flowLabels[1], 'Flow labels at second hop over time', 'label', 'label_1', y_lim=[0,3])
    if (args.label_2 or args.all):
        plot_flow_data(flowCtrlTimes, flowLabels[2], 'Flow labels at third hop over time', 'label', 'label_2', y_lim=[0,3])
    if (args.linkCap or args.all):
        plot_flow_data(flowCtrlTimes, flowLinkCaps, 'Flow linkCap measurements over time', 'rate (Gbps)', 'linkCap', y_lim=[0,MAX_RATE+1])
    if (args.sumSat or args.all):
        plot_flow_data(flowCtrlTimes, flowSumSats, 'Flow sumSat state over time', 'rate (Gbps)', 'sumSat', y_lim=[0,MAX_RATE+1])
    if (args.numFlows or args.all):
        plot_flow_data(flowCtrlTimes, flowNumFlows, 'Flow numFlows state over time', 'numFlows', 'numFlows')
    if (args.numSat or args.all):
        plot_flow_data(flowCtrlTimes, flowNumSats, 'Flow numSat state over time', 'numSat', 'numSat')
    if (args.maxSat or args.all):
        plot_flow_data(flowCtrlTimes, flowNewMaxSats, 'Flow maxSat state over time', 'rate (Gbps)', 'maxSat', y_lim=[0,MAX_RATE+1])
    if (args.R or args.all):
        plot_flow_data(flowCtrlTimes, flowRs, 'Flow R measurements over time', 'rate (Gbps)', 'R', y_lim=[0,MAX_RATE+1])
    if (args.nf0_data or args.nf1_data or args.nf2_data or args.nf3_data):
        plot_data_q_data(args)
    if (args.nf0_ctrl or args.nf1_ctrl or args.nf2_ctrl or args.nf3_ctrl):
        plot_ctrl_q_data(args)    
    if (args.rate or args.all):
        plot_flow_data(flowAvgTimes, flowRates, 'Measured flow rates over time (avg interval = {} sec)'.format(RATE_AVG_INTERVAL), 'rate (Gbps)', 'flow_rates', y_lim=[0,MAX_RATE+1])
    if (args.seq or args.all):
        plot_flow_data(flowDataTimes, flowSeqNos, 'Flow Sequence Numbers over time', 'seqNo', 'seqNo')

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
    parser.add_argument('--alloc_0', action='store_true', default=False, help='plot the allocation of each flow at their first hop')
    parser.add_argument('--alloc_1', action='store_true', default=False, help='plot the allocation of each flow at their second hop')
    parser.add_argument('--alloc_2', action='store_true', default=False, help='plot the allocation of each flow at their third hop')
    parser.add_argument('--label_0', action='store_true', default=False, help='plot the label of each flow at their first hop')
    parser.add_argument('--label_1', action='store_true', default=False, help='plot the label of each flow at their second hop')
    parser.add_argument('--label_2', action='store_true', default=False, help='plot the label of each flow at their third hop')
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
    parser.add_argument('--rate', action='store_true', default=False, help='plot the measured data rate of each flow')
    parser.add_argument('--seq', action='store_true', default=False, help='plot the data seqNo for each flow')
    parser.add_argument('--workload', type=str, default="", help="the file that specifies the workload that was run to produce these results")
    parser.add_argument('--out', type=str, default="", help="the output directory to store results")
    args = parser.parse_args()

    global OUT_DIR
    OUT_DIR = args.out

    read_pcap_pkts(args.logged_pkts)
    if (args.rtt):
        report_rtt()

    calc_flow_stats()
    if (args.workload != ""):
        log_CT(args.workload) 
    make_plots(args=args)


if __name__ == "__main__":
    main()
