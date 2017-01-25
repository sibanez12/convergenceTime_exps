
"""
This file defines the top level functions:
(1) setupExperiment
(2) runExperiment
(3) reportResults
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
import subprocess, shlex, math, sys, os, socket

from workload import Workload
from mp_max_min import MPMaxMin
from get_ctime import *
from tcpprobe import *

class CT_Experiment:

    """
    starts the rate monitor on each host
    starts iperf server on each destination machine
    """
    def __init__(self, workload):

        kill_logging = 'ssh root@{0} "pkill -u root cat"' 

        # kill all currently running logging processes if there are any
        for host in workload.allHosts:
            command = kill_logging.format(host)
            rc = self.runCommand(command)
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)          
 
        unload_tcp_probe = 'ssh root@{0} "modprobe -r tcp_probe"'
        load_tcp_probe = 'ssh root@{0} "modprobe tcp_probe port=5001 full=1"'
        log_file = '/tmp/tcpprobe_{0}.log' 
        write_log_file = 'ssh root@{0} "cat /proc/net/tcpprobe >%s"' % log_file   

        self.workload = workload        
        self.logging_processes = []

        # setup tcp_probe
        for host in workload.allHosts:
            self.runCommand(unload_tcp_probe.format(host))
            self.runCommand(load_tcp_probe.format(host))
            p = self.startProcess(write_log_file.format(host))
            self.logging_processes.append((host, p))
    
        kill_iperf = 'ssh root@{0} "pkill -u root iperf"'
        start_iperf_server = 'ssh root@{0} "iperf -s"'
        self.iperf_servers = []
        self.iperf_clients = []

        # start iperf server on each destination
        for host in workload.dstHosts:
            rc = self.runCommand(kill_iperf.format(host))
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(kill_iperf.format(host))
            p = self.startProcess(start_iperf_server.format(host))
            self.iperf_servers.append((host, p))

    """
    get the global start time, distributed to each of the
    required hosts, and run the experiment 
    """
    def runExperiment(self):
        currTime = get_real_time()
        expStartTime = int(math.floor(currTime + 5)) # start the experiment 5 seconds from now

        start_iperf_client = os.path.expandvars('ssh root@{0} "$CT_EXP_DIR/exec_at {1} /usr/bin/iperf -c {2}"')

        # start iperf clients on each src machine
        for flow in self.workload.flows:
            srcHost = self.workload.ipHostMap[flow['srcIP']]
            command = start_iperf_client.format(srcHost, expStartTime, flow['dstIP'])
            p = self.startProcess(command)
            self.iperf_clients.append((srcHost, p))

        # wait for all iperf clients to finish
        for (host, iperf_client) in self.iperf_clients:
            print "Waiting for iperf client on host {0} ...".format(host)
            iperf_client.wait()
            print "iperf client on host {0} finished with return code: {1}".format(host, iperf_client.returncode)

        self.cleanupExperiment()

    # kill all tcpprobe logging processes
    # kill all iperf servers
    # copy all tcpprobe log files to single location
    def cleanupExperiment(self):

        # kill all tcpprobe logging processes
        for (host, log_process) in self.logging_processes:
            log_process.kill() 
            command = 'ssh root@{0} "pkill -u root cat"'.format(host) 
            rc = self.runCommand(command) 
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)

        # kill all iperf servers
        for (host, server) in self.iperf_servers:
            server.kill() 
            command = 'ssh root@{0} "pkill -u root iperf"'.format(host)
            rc = self.runCommand(command) 
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)             

        log_dir = os.path.expandvars('$CT_EXP_DIR/logs/')
        copy_log_file = 'scp root@{0}:~/../tmp/tcpprobe_* %s' % log_dir
        # copy all log files to single location
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        for host in self.workload.allHosts:
            self.runCommand(copy_log_file.format(host)) 

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
   
    # parse the tcpprobe log files in $CT_EXP_DIR/logs to determine
    #   convergence time of each flow 
    def getResults(self):
        results = {}
        results['rates'] = [] # entry i is like: (time_i, rate_i)
        results['convTimes'] = []
        results['cwnd'] = [] # entry i is like: (time_i, cwnd_i)
        # calculate the ideal rates for the particular workload
        wf = MPMaxMin(self.workload)       
        idealRates = wf.maxmin_x
       
        # get the rates and convergence times of each flow
        for flowID, flow in zip(range(len(self.workload.flows)), self.workload.flows):
            host = self.workload.ipHostMap[flow['srcIP']]
            logFile = os.path.expandvars('$CT_EXP_DIR/logs/tcpprobe_{0}.log'.format(host))
            time, rate = get_tcpprobe_rate(logFile, flow['srcIP'], flow['dstIP'])
            results['rates'].append((time, rate))
            results['convTimes'].append(self.getCTtime(time, rate, idealRates[flowID]))
            time2, cwnd = get_tcpprobe_cwnd(logFile, flow['srcIP'], flow['dstIP'])
            results['cwnd'].append((time2, cwnd))

        return results

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

    def reportResults(self, results):

        self.out_dir = os.path.expandvars('$CT_EXP_DIR/out')
        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir) 

        self.plotFlowRates(results)
        self.plotCwnd(results) 
        self.plotCTCDF(results)
 
    def plotCTCDF(self, results):
        # plot the CDF of convergence times for each flow
        sortData = np.sort(results['convTimes'])
        yvals = np.arange(len(sortData))/float(len(sortData))
        plt.plot(sortData, yvals, marker='o')
    
        plt.ylabel('CDF')
        plt.xlabel('Convergence Time (sec)')
        plt.title('CDF of convergence times')
        plt.grid()
    
        plot_filename = self.out_dir + '/CT_CDF.pdf'
        pp = PdfPages(plot_filename)
        pp.savefig()
        pp.close()
        print "Saved plot: ", plot_filename

    def plotFlowRates(self, results): 
        cutoff = 0.05
        # plot all flow rates on single plot for now
        for (flowID, (time, rate)) in zip(range(len(results['rates'])), results['rates']):
            t, r = self.cutToTime(time, rate, cutoff)
            plt.plot(t, r, label='flow {0}'.format(flowID), marker='o')
        plt.legend() 
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
        cutoff = 0.05
        # plot all flow rates on single plot for now
        for (flowID, (time, cwnd)) in zip(range(len(results['cwnd'])), results['cwnd']):
            t, c = self.cutToTime(time, cwnd, cutoff)
            plt.plot(t, c, label='flow {0}'.format(flowID), marker='o')
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
 
    def cutToTime(self, time, vals, cutoff):
        new_time = [t for t in time if t <= cutoff]
        new_vals = [v for (v,t) in zip(vals, time) if t <= cutoff]
        return new_time, new_vals



