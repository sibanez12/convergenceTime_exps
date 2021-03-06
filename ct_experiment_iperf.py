
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

TCP_VERSION = "reno"

#WINDOW_SIZE = 1000

class CT_Experiment:

    """
    starts the rate monitor on each host
    starts iperf server on each destination machine
    """
    def __init__(self, workload):

        self.workload = workload        
        self.logging_processes = []
        self.iperf_servers = []
        self.iperf_clients = []

        kill_logging = 'ssh root@{0} "pkill -u root cat"'
        unload_tcp_probe = 'ssh root@{0} "modprobe -r tcp_probe"'
        load_tcp_probe = 'ssh root@{0} "modprobe tcp_probe port=0 full=1"' # port=0 means match on all ports
        log_file = '/tmp/tcpprobe_{0}.log' 
        write_log_file = 'ssh root@{0} "cat /proc/net/tcpprobe >%s"' % log_file

        # kill all currently running logging processes if there are any
        for host in workload.allHosts:
            rc = self.runCommand(kill_logging.format(host))
            if rc not in [0,1]:
                print >> sys.stderr, "ERROR: {0} -- failed".format(command)          
            self.runCommand(unload_tcp_probe.format(host))
            self.runCommand(load_tcp_probe.format(host))
            p = self.startProcess(write_log_file.format(host))
            self.logging_processes.append((host, p))

        for flow in workload.flows:
            self.setupFlow(flow)

        time.sleep(2) # give the iperf3 servers time to set up
 
    def setupFlow(self, flow):   
        start_iperf_server = 'ssh root@{0} "iperf3 -s -p %d"' % (flow['port'])

        # start iperf server on the destination
        dstHost = flow['dstHost']
        p = self.startProcess(start_iperf_server.format(dstHost))
        self.iperf_servers.append((dstHost, p))

    """
    get the global start time, distributed to each of the
    required hosts, and run the experiment 
    """
    def runExperiment(self):
        currTime = get_real_time()
        expStartTime = int(math.floor(currTime + 5)) # start the experiment 5 seconds from now

        start_iperf_client = os.path.expandvars('ssh root@{0} "$CT_EXP_DIR/exec_at {1} /usr/bin/iperf3 -p {2} --linux-congestion {3} -c {4}"')

        # start iperf clients on each src machine
        for flow in self.workload.flows:
            command = start_iperf_client.format(flow['srcHost'], expStartTime, flow['port'], TCP_VERSION, flow['dstIP'])
            p = self.startProcess(command)
            self.iperf_clients.append((flow['srcHost'], p))

        # wait for all iperf clients to finish
        for (host, iperf_client) in self.iperf_clients:
            print "Waiting for iperf client on host {0} ...".format(host)
            iperf_client.wait()
            rc = iperf_client.returncode
            print "iperf client on host {0} finished with return code: {1}".format(host, rc)
            if rc != 0:
                output, error = iperf_client.communicate()
                print("iperf_client failed %s %s" % (output, error))

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
        for flow in self.workload.flows:
            self.runCommand(copy_log_file.format(flow['srcHost'])) 

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
        results['ssthresh'] = [] # entry i is like: (time_i, ssthresh_i)
        results['snd_wnd'] = [] # entry i is like: (time_i, snd_wnd_i)
        results['rcv_wnd'] = [] # entry i is like: (time_i, rcv_wnd_i)
        # calculate the ideal rates for the particular workload
        wf = MPMaxMin(self.workload)       
        idealRates = wf.maxmin_x
       
        # get the rates and convergence times of each flow
        for flowID, flow in zip(range(len(self.workload.flows)), self.workload.flows):
            host = self.workload.ipHostMap[flow['srcIP']]
            logFile = os.path.expandvars('$CT_EXP_DIR/logs/tcpprobe_{0}.log'.format(host))
            time1, rate, _cwnd, _srtt = get_tcpprobe_stats(logFile, flow['srcIP'], flow['dstIP'], flow['port'])
            time2, cwnd, srtt, ssthresh, snd_wnd, rcv_wnd = get_tcpprobe_cwnd_srtt(logFile, flow['srcIP'], flow['dstIP'], flow['port'])
            results['rates'].append((time1, rate))
            results['convTimes'].append(self.getCTtime(time1, rate, idealRates[flowID]))
            results['cwnd'].append((time2, cwnd))
            results['srtt'].append((time2, srtt))
            results['ssthresh'].append((time2, ssthresh))
            results['snd_wnd'].append((time2, snd_wnd))
            results['rcv_wnd'].append((time2, rcv_wnd))

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
        self.plotSsthresh(results) 
        self.plotSnd_wnd(results) 
        self.plotRcv_wnd(results) 
 
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
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, cwnd)) in zip(range(len(results['cwnd'])), results['cwnd']):
            csv_file = self.out_dir + '/flow_{0}_cwnd.csv'.format(flowID) 
            self.recordData(time, cwnd, csv_file)
#            t, c = self.cutToTime(time, cwnd, cutoff)
#            plt.plot(t, c, label='flow {0}'.format(flowID), marker='o')
#        plt.legend() 
#        plt.title('Congestion Window over time')
#        plt.xlabel('time (sec)')
#        plt.ylabel('congestion window')
#
#        plot_filename = self.out_dir + '/flow_cwnd.pdf'
#        pp = PdfPages(plot_filename)
#        pp.savefig()
#        pp.close()
#        print "Saved plot: ", plot_filename
#        plt.cla()

    def plotSrtt(self, results): 
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, srtt)) in zip(range(len(results['srtt'])), results['srtt']):
            csv_file = self.out_dir + '/flow_{0}_srtt.csv'.format(flowID) 
            self.recordData(time, srtt, csv_file)
#            t, s = self.cutToTime(time, srtt, cutoff)
#            plt.plot(t, s, label='flow {0}'.format(flowID), marker='o')
#        plt.legend() 
#        plt.title('Smoothed RTT over time')
#        plt.xlabel('time (sec)')
#        plt.ylabel('Smoothed RTT')
#
#        plot_filename = self.out_dir + '/flow_srtt.pdf'
#        pp = PdfPages(plot_filename)
#        pp.savefig()
#        pp.close()
#        print "Saved plot: ", plot_filename
#        plt.cla()

    def plotSsthresh(self, results): 
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, ssthresh)) in zip(range(len(results['ssthresh'])), results['ssthresh']):
            csv_file = self.out_dir + '/flow_{0}_ssthresh.csv'.format(flowID) 
            self.recordData(time, ssthresh, csv_file)
#            t, s = self.cutToTime(time, ssthresh, cutoff)
#            plt.plot(t, s, label='flow {0}'.format(flowID), marker='o')
#        plt.legend() 
#        plt.title('Slow Start Threshhold over time')
#        plt.xlabel('time (sec)')
#        plt.ylabel('SS Thresh (MSS)')
#
#        plot_filename = self.out_dir + '/flow_ssthresh.pdf'
#        pp = PdfPages(plot_filename)
#        pp.savefig()
#        pp.close()
#        print "Saved plot: ", plot_filename
#        plt.cla()
 
    def plotSnd_wnd(self, results): 
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, snd_wnd)) in zip(range(len(results['snd_wnd'])), results['snd_wnd']):
            csv_file = self.out_dir + '/flow_{0}_snd_wnd.csv'.format(flowID) 
            self.recordData(time, snd_wnd, csv_file)
#            t, s = self.cutToTime(time, snd_wnd, cutoff)
#            plt.plot(t, s, label='flow {0}'.format(flowID), marker='o')
#        plt.legend() 
#        plt.title('Send Window over time')
#        plt.xlabel('time (sec)')
#        plt.ylabel('send window (MSS)')
#
#        plot_filename = self.out_dir + '/flow_snd_wnd.pdf'
#        pp = PdfPages(plot_filename)
#        pp.savefig()
#        pp.close()
#        print "Saved plot: ", plot_filename
#        plt.cla()

    def plotRcv_wnd(self, results): 
        cutoff = 10.0
        # plot all flow rates on single plot for now
        for (flowID, (time, rcv_wnd)) in zip(range(len(results['rcv_wnd'])), results['rcv_wnd']):
            csv_file = self.out_dir + '/flow_{0}_rcv_wnd.csv'.format(flowID) 
            self.recordData(time, rcv_wnd, csv_file)
#            t, r = self.cutToTime(time, rcv_wnd, cutoff)
#            plt.plot(t, r, label='flow {0}'.format(flowID), marker='o')
#        plt.legend() 
#        plt.title('Receive Window over time')
#        plt.xlabel('time (sec)')
#        plt.ylabel('Receive Window (MSS)')
#
#        plot_filename = self.out_dir + '/flow_rcv_wnd.pdf'
#        pp = PdfPages(plot_filename)
#        pp.savefig()
#        pp.close()
#        print "Saved plot: ", plot_filename
#        plt.cla()


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






