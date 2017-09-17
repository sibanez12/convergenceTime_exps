
"""
This file defines the top level functions:
(1) setupExperiment
(2) runExperiment
(3) reportResults
"""

#import matplotlib
#matplotlib.use('Agg')
#import matplotlib.pyplot as plt
#from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import subprocess, shlex, math, sys, os, socket

from workload import Workload
from mp_max_min import MPMaxMin
from get_ctime import *
from ip_info import ip_info
from plot_log import read_pcap_pkts, calc_flow_stats, make_plots

LOGGING_IFACES = [('han-1.stanford.edu', 'eth3'), ('han-3.stanford.edu', 'eth6'), ('han-5.stanford.edu', 'eth5')]
#LOGGING_IFACE = ('han-2.stanford.edu', 'eth3')

class CT_Experiment:

    """
    starts the rate monitor on each host
    starts iperf server on each destination machine
    """
    def __init__(self, workload, config_hosts):

        self.workload = workload        
        self.iperf_servers = []
        self.iperf_clients = []
        self.logging_processes = []

        if (config_hosts):
            self.config_hosts()

        currTime = get_real_time()
        self.startLogging() 

        for flow in workload.flows:
            self.setupFlow(flow)

    """
    Add the necessary routes to the linux routing tables and add populate the ARP table entries
    """
    def config_hosts(self):
        add_ip = 'ssh root@{0} "ifconfig {1} {2} netmask 255.255.255.0"'
        for IP in self.workload.allIPs:
            command = add_ip.format(ip_info[IP]['hostname'], ip_info[IP]['iface'], IP)
            rc = self.runCommand(command)
            if rc != 0:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)

            otherIPs = [x for x in self.workload.allIPs if x != IP]
            self.add_routes(IP, otherIPs)

    def add_routes(self, thisIP, otherIPs):
        add_route = 'ssh root@{0} "ip route add {1} dev {2}"'
        add_arp = 'ssh root@{0} "arp -i {1} -s {2} {3}"'
        thisHost = ip_info[thisIP]['hostname']
        thisIface = ip_info[thisIP]['iface']
        for otherIP in otherIPs:
            command = add_route.format(thisHost, otherIP, thisIface)
            rc = self.runCommand(command)
            if rc != 0:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)

            otherMAC = ip_info[otherIP]['mac']
            command = add_arp.format(thisHost, thisIface, otherIP, otherMAC) 
            rc = self.runCommand(command)
            if rc != 0:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)


    """
    Start capturing the logged packets
    """
    def startLogging(self):
        start_tcpdump = 'ssh root@{0} "tcpdump -i {1} -w /tmp/exp_log_{0}.pcap"'

        # start logging
        for (host, iface) in LOGGING_IFACES:
            p = self.startProcess(start_tcpdump.format(host, iface))
            self.logging_processes.append((host, p))

    """
    Start the iperf servers
    """
    def setupFlow(self, flow):
        start_iperf_server = 'ssh root@{0} "iperf3 -s -p %d"' % flow['port']

        # start iperf server on the destination
        dstHost = flow['dstHost']
        p = self.startProcess(start_iperf_server.format(dstHost))
        self.iperf_servers.append((dstHost, p))

    """
    get the global start time, distributed to each of the
    required hosts, and run the experiment 
    """
    def runExperiment(self, tcp_version):
        currTime = get_real_time()
        expStartTime = int(math.floor(currTime + 5)) # start the experiment 5 seconds from now

        start_iperf_client = os.path.expandvars('ssh root@{0} "$CT_EXP_DIR/exec_at {1} {2} /usr/bin/iperf3 -p {3} -c {4} -t {5} -C {6}"')

        # start iperf clients on each src machine
        for flow in self.workload.flows:
            startTime = expStartTime + flow['startTime']
            startTime_sec = int(startTime)
            startTime_nsec = int((startTime - int(startTime))*(10**9))
            command = start_iperf_client.format(flow['srcHost'], startTime_sec, startTime_nsec, flow['port'], flow['dstIP'], flow['duration'], tcp_version)
            p = self.startProcess(command)
            self.iperf_clients.append((flow['srcHost'], p))

        # wait for all iperf clients to finish
        for (host, iperf_client) in self.iperf_clients:
            print "Waiting for iperf client on host {0} ...".format(host)
            iperf_client.wait()
            print "iperf client on host {0} finished with return code: {1}".format(host, iperf_client.returncode)

        self.cleanupExperiment()

    # kill all tcpdump logging processes
    # kill all iperf servers
    def cleanupExperiment(self):

        # kill all tcpprobe logging processes
        for (host, log_process) in self.logging_processes:
            log_process.kill() 
            command = 'ssh root@{0} "pkill -u root tcpdump"'.format(host) 
            rc = self.runCommand(command) 
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)

        # kill all iperf servers
        for (host, server) in self.iperf_servers:
            server.kill() 
            command = 'ssh root@{0} "pkill -u root iperf3"'.format(host)
            rc = self.runCommand(command) 
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)             

        # copy log files
        log_dir = os.path.expandvars('$CT_EXP_DIR/logs/')
        copy_log_file = 'scp root@{0}:/tmp/exp_log_{0}.pcap %s' % log_dir
        os.system(os.path.expandvars('rm -rf $CT_EXP_DIR/logs/'))
        os.makedirs(log_dir)
        # copy the log file
        for (host, iface) in LOGGING_IFACES:
            self.runCommand(copy_log_file.format(host)) 

        # copy the workload file into the log directory
        os.system('cp {} {}'.format(self.workload.flowsFile, log_dir))

    def runCommand(self, command):
        print "----------------------------------------"
        print "Running Command:\n"
        print "-->$ ", command
        print "----------------------------------------"
        return subprocess.call(command, shell=True)
    
    def startProcess(self, command):
        print "----------------------------------------"
        print "Starting Process:\n"
        print "-->$ ", command
        print "----------------------------------------"
        return subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.STDOUT) 
   
#    # parse the tcpprobe log files in $CT_EXP_DIR/logs to determine
#    #   convergence time of each flow 
#    def getResults(self):
#        results = {}
#        results['rates'] = [] # entry i is like: (time_i, rate_i)
#        results['convTimes'] = []
#        results['cwnd'] = [] # entry i is like: (time_i, cwnd_i)
#        results['srtt'] = [] # entry i is like: (time_i, srtt_i)
#        # calculate the ideal rates for the particular workload
#        wf = MPMaxMin(self.workload)       
#        idealRates = wf.maxmin_x
#       
#        # get the rates and convergence times of each flow
#        for flowID, flow in zip(range(len(self.workload.flows)), self.workload.flows):
#            host = self.workload.ipHostMap[flow['srcIP']]
#            logFile = os.path.expandvars('$CT_EXP_DIR/logs/tcpprobe_{0}.log'.format(host))
#            time, rate, cwnd, srtt = get_tcpprobe_stats(logFile, flow['srcIP'], flow['dstIP'], flow['port'])
#            results['rates'].append((time, rate))
##            results['convTimes'].append(self.getCTtime(time, rate, idealRates[flowID]))
#            results['cwnd'].append((time, cwnd))
#            results['srtt'].append((time, srtt))
#
#        return results

    """
    Determine how long it takes for rate to converge to idealRate.
    time: list of time values (sec)
    convergence is defined as within 10% for at least 1ms
    """
    def getCTtime(self, time, rate, idealRate):
        dur = 0.001;
        interval = time[1] - time[0]
        percent = 0.1
        numSampNeeded = math.ceil(dur/interval)

        numConverged = 0
        for t, r in zip(time, rate):
            if r >= (1-percent)*idealRate and r <= (1+percent)*idealRate:
                 numConverged += 1 
                 if numConverged == numSampNeeded:
                     return t # converged!
            else:
                 numConverged = 0
        return -1 # failed to converge

    """
    Create the result plots from the logged pkts
    """
    def reportResults(self):
        log_file = os.path.expandvars('$CT_EXP_DIR/logs/exp_log.pcap')
        read_pcap_pkts(log_file)
        calc_flow_stats()
        make_plots(True, True, True)
        
 
    def plotCTCDF(self, results):
        # plot the CDF of convergence times for each flow
        sortData = np.sort(results['convTimes'])
        yvals = np.arange(len(sortData))/float(len(sortData))
        plt.plot(sortData, yvals, marker='o')
    
        plt.ylabel('CDF')
        plt.xlabel('Convergence Time (sec)')
        plt.title('CDF of convergence times')
        plt.grid()
   
        base_fname = self.out_dir + '/CT_CDF'
        self.recordData(sortData, yvals, base_fname + '.csv')

        plot_filename = base_fname + '.pdf' 
        pp = PdfPages(plot_filename)
        pp.savefig()
        pp.close()
        print "Saved plot: ", plot_filename

    def plotFlowRates(self, results): 
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, rate)) in zip(range(len(results['rates'])), results['rates']):
            csv_file = self.out_dir + '/flow_{0}_rate.csv'.format(flowID) 
            self.recordData(time, rate, csv_file)
            #time, rate = self.cutToTime(time, rate, cutoff)
            plt.plot(time, rate, label='flow {0}'.format(flowID), marker='o')
        plt.legend(loc='lower right') 
        plt.title('Flow Rates over time')
        plt.xlabel('time (sec)')
        plt.ylabel('rate (Gbps)')

        plot_filename = self.out_dir + '/flow_rates.pdf'
        pp = PdfPages(plot_filename)
        pp.savefig()
        pp.close()
        print "Saved plot: ", plot_filename
        plt.cla()
      
    def plotCwnd(self, results): 
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, cwnd)) in zip(range(len(results['cwnd'])), results['cwnd']):
            csv_file = self.out_dir + '/flow_{0}_cwnd.csv'.format(flowID) 
            self.recordData(time, cwnd, csv_file)
            #time, cwnd = self.cutToTime(time, cwnd, cutoff)
            plt.plot(time, cwnd, label='flow {0}'.format(flowID), marker='o')
        plt.legend() 
        plt.title('Congestion Window over time')
        plt.xlabel('time (sec)')
        plt.ylabel('congestion window')

        plot_filename = self.out_dir + '/flow_cwnd.pdf'
        pp = PdfPages(plot_filename)
        pp.savefig()
        pp.close()
        print "Saved plot: ", plot_filename
        plt.cla()

    def plotSrtt(self, results): 
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, srtt)) in zip(range(len(results['srtt'])), results['srtt']):
            csv_file = self.out_dir + '/flow_{0}_srtt.csv'.format(flowID) 
            self.recordData(time, srtt, csv_file)
            #time, srtt = self.cutToTime(time, srtt, cutoff)
            plt.plot(time, srtt, label='flow {0}'.format(flowID), marker='o')
        plt.legend() 
        plt.title('Smoothed RTT over time')
        plt.xlabel('time (sec)')
        plt.ylabel('Smoothed RTT')

        plot_filename = self.out_dir + '/flow_srtt.pdf'
        pp = PdfPages(plot_filename)
        pp.savefig()
        pp.close()
        print "Saved plot: ", plot_filename
        plt.cla()
 
 
    def cutToTime(self, time, vals, cutoff):
        new_time = [t for t in time if t <= cutoff]
        new_vals = [v for (v,t) in zip(vals, time) if t <= cutoff]
        return new_time, new_vals

    def recordData(self, xvals, yvals, filename):
        try:
            os.remove(filename)
        except OSError:
            pass

        with open(filename, 'w') as f:
            for x, y in zip(xvals, yvals):
                f.write('{0}, {1}\n'.format(x,y))






