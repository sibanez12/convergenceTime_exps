
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
import subprocess, shlex, math, sys, os, socket, time

from workload import Workload
from mp_max_min import MPMaxMin
from get_ctime import *
from tcpprobe import *

#BUFSIZE = 2048
SND_MSG_LEN = 1500*10000
SND_BUFSIZE = 2**21 #2048 #4096 #262144

RCV_LEN = 4096

DURATION = 10
CUTOFF = 10

TCP_VERSION = "reno"

class CT_Experiment:

    """
    starts the rate monitor on each host
    starts tcp server on each destination machine
    """
    def __init__(self, workload):

        self.workload = workload        
        self.logging_processes = []
        self.tcp_servers = []
        self.tcp_clients = []

        kill_logging = 'ssh root@{0} "pkill -u root cat"' 

        unload_tcp_probe = 'ssh root@{0} "modprobe -r tcp_probe"'
        load_tcp_probe = 'ssh root@{0} "modprobe tcp_probe port=0 full=1"' # port=0 means match on all ports
        log_file = '/tmp/tcpprobe_{0}.log' 
        write_log_file = 'ssh root@{0} "cat /proc/net/tcpprobe >%s"' % log_file   

        set_tcp_version = 'ssh root@{0} "echo {1} > /proc/sys/net/ipv4/tcp_congestion_control"'

        for host in workload.allHosts:
            # kill all currently running logging processes if there are any
            command = kill_logging.format(host)
            rc = self.runCommand(command)
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)          
            
            # load tcp_probe on the source host
            self.runCommand(unload_tcp_probe.format(host))
            self.runCommand(load_tcp_probe.format(host))
            p = self.startProcess(write_log_file.format(host))
            self.logging_processes.append((host, p))

            # set TCP congestion control algorithm to use
            self.runCommand(set_tcp_version.format(host, TCP_VERSION)) 

        for flow in workload.flows:
            self.setupFlow(flow)
        # sleep to give the servers time to set up
        time.sleep(3)
 
    def setupFlow(self, flow):   
        start_tcp_server = os.path.expandvars('ssh root@{0} "$CT_EXP_DIR/run_server.py {1} {2} {3}"'.format(flow['dstHost'], flow['dstIP'], flow['port'], RCV_LEN))

        # start tcp server on the destination
        p = self.startProcess(start_tcp_server)
        self.tcp_servers.append((flow['dstHost'], p))

    """
    get the global start time, distributed to each of the
    required hosts, and run the experiment 
    """
    def runExperiment(self):
        currTime = get_real_time()
        expStartTime = int(math.floor(currTime + 5)) # start the experiment 5 seconds from now

        start_tcp_client = os.path.expandvars('ssh root@{0} "$CT_EXP_DIR/run_client.py {1} {2} {3} {4} {5} {6}"')

        # start tcp clients on each src machine
        for flow in self.workload.flows:
            command = start_tcp_client.format(flow['srcHost'], flow['dstIP'], flow['port'], SND_BUFSIZE, SND_MSG_LEN, expStartTime, DURATION)
            p = self.startProcess(command)
            self.tcp_clients.append((flow['srcHost'], p))

        # wait for all tcp clients to finish
        for (host, tcp_client) in self.tcp_clients:
            print "Waiting for tcp client on host {0} ...".format(host)
            tcp_client.wait()
            rc = tcp_client.returncode
            print "tcp client on host {0} finished with return code: {1}".format(host, rc)
            if rc != 0: 
                output, error = tcp_client.communicate()
                print("tcp_client failed %s %s" % (output, error))

        self.cleanupExperiment()

    # kill all tcpprobe logging processes
    # kill all tcp servers
    # copy all tcpprobe log files to single location
    def cleanupExperiment(self):

        # kill all tcpprobe logging processes
        for (host, log_process) in self.logging_processes:
            log_process.kill() 
            command = 'ssh root@{0} "pkill -u root cat"'.format(host) 
            rc = self.runCommand(command) 
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)

        # kill all tcp servers
        for (host, server) in self.tcp_servers:
            server.kill() 
            command = 'ssh root@{0} "pkill -u root python"'.format(host)
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
        results['srtt'] = [] # entry i is like: (time_i, srtt_i)
        # calculate the ideal rates for the particular workload
        wf = MPMaxMin(self.workload)       
        idealRates = wf.maxmin_x
       
        # get the rates and convergence times of each flow
        for flowID, flow in zip(range(len(self.workload.flows)), self.workload.flows):
            host = self.workload.ipHostMap[flow['srcIP']]
            logFile = os.path.expandvars('$CT_EXP_DIR/logs/tcpprobe_{0}.log'.format(host))
            time1, rate, _cwnd, _srtt = get_tcpprobe_stats(logFile, flow['srcIP'], flow['dstIP'], flow['port'])
            time2, cwnd, srtt = get_tcpprobe_cwnd_srtt(logFile, flow['srcIP'], flow['dstIP'], flow['port'])
            results['rates'].append((time1, rate))
            results['convTimes'].append(self.getCTtime(time1, rate, idealRates[flowID]))
            results['cwnd'].append((time2, cwnd))
            results['srtt'].append((time2, srtt))

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
        os.system(os.path.expandvars('rm $CT_EXP_DIR/out/*'))

        self.plotFlowRates(results)
        self.plotCwnd(results) 
        self.plotSrtt(results) 
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
   
        base_fname = self.out_dir + '/CT_CDF'
        self.recordData(sortData, yvals, base_fname + '.csv')

        plot_filename = base_fname + '.pdf' 
        pp = PdfPages(plot_filename)
        pp.savefig()
        pp.close()
        print "Saved plot: ", plot_filename

    def plotFlowRates(self, results): 
        cutoff = CUTOFF
        # plot all flow rates on single plot for now
        for (flowID, (time, rate)) in zip(range(len(results['rates'])), results['rates']):
            csv_file = self.out_dir + '/flow_{0}_rate.csv'.format(flowID) 
            t, r = self.cutToTime(time, rate, cutoff)
            self.recordData(t, r, csv_file)
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
        cutoff = CUTOFF
        # plot all flow rates on single plot for now
        for (flowID, (time, cwnd)) in zip(range(len(results['cwnd'])), results['cwnd']):
            csv_file = self.out_dir + '/flow_{0}_cwnd.csv'.format(flowID) 
            t, c = self.cutToTime(time, cwnd, cutoff)
            self.recordData(t, c, csv_file)
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

    def plotSrtt(self, results): 
        cutoff = CUTOFF
        # plot all flow rates on single plot for now
        for (flowID, (time, srtt)) in zip(range(len(results['srtt'])), results['srtt']):
            csv_file = self.out_dir + '/flow_{0}_srtt.csv'.format(flowID) 
            t, s = self.cutToTime(time, srtt, cutoff)
            self.recordData(t, s, csv_file)
            plt.plot(t, s, label='flow {0}'.format(flowID), marker='o')
        plt.legend() 
        plt.title('Smoothed RTT over time')
        plt.xlabel('time (sec)')
        plt.ylabel('Smoothed RTT (us)')

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






