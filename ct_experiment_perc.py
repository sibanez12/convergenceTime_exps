
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
import subprocess, math, sys, os, socket, time

from workload import Workload
from mp_max_min import MPMaxMin
from get_ctime import *
from ip_info import ip_info
from plot_log import read_pcap_pkts, calc_flow_stats, make_plots

LOGGING_IFACES = ['han-1.stanford.edu', 'han-3.stanford.edu', 'han-5.stanford.edu']

# wait this long after starting up perc application before sending first packets
# so that the destination has a chance to set up first
START_DELAY = 3 # seconds
WAIT_TO_KILL = 2

LOGGING_THREADS = 1

class CT_Experiment:

    """
    starts the rate monitor on each host
    starts iperf server on each destination machine
    """
    def __init__(self, workload):

        self.workload = workload        
        self.perc_apps = []
#        self.logging_processes = []

#        self.startLogging() 

#        for flow in workload.flows:
#            self.setupFlow(flow)

#    """
#    Start capturing the logged packets
#    """
#    def startLogging(self):
#        start_tcpdump = 'ssh root@{0} "tcpdump -i {1} -w /tmp/exp_log_{0}.pcap"'
#
#        # start logging
#        for (host, iface) in LOGGING_IFACES:
#            p = self.startProcess(start_tcpdump.format(host, iface))
#            self.logging_processes.append((host, p))

#    """
#    Start the iperf servers
#    """
#    def setupFlow(self, flow):
#        start_iperf_server = 'ssh root@{0} "iperf3 -s -p %d"' % flow['port']
#
#        # start iperf server on the destination
#        dstHost = flow['dstHost']
#        p = self.startProcess(start_iperf_server.format(dstHost))
#        self.iperf_servers.append((dstHost, p))

    """
    get the global start time, distributed to each of the
    required hosts, and run the experiment 
    """
    def runExperiment(self):
        currTime = get_real_time()
        expStartTime = int(math.floor(currTime + 5)) # start the experiment 5 seconds from now
        
        # start the perc applications
        for host, host_dict in self.workload.allHosts.items():
            flow = host_dict['flow']
            if flow is not None:
                # this host is the source of a flow
                start_perc_app = os.path.expandvars('ssh root@{} "$CT_EXP_DIR/exec_at {} {} $MOONGEN_DIR/build/libmoon $MOONGEN_DIR/examples/test_perc_control.lua -d {} -s {} -n {} -t {} -o {} -w {} -c {} -f {} 0 {}" > {}')
                startTime = expStartTime + flow['startTime']
                startTime_sec = int(startTime)
                startTime_nsec = int((startTime - int(startTime))*(10**9))
                dst_mac = ip_info[flow['dstIP']]['mac']
                src_mac = ip_info[flow['srcIP']]['mac']
                log_port = '1' if host in LOGGING_IFACES else ''
                command = start_perc_app.format(host, startTime_sec, startTime_nsec, dst_mac, src_mac, flow['numConn'], flow['duration'], flow['offset_id'], START_DELAY, LOGGING_THREADS, '/tmp/perc-log-{}.pcap'.format(host), log_port, 'logs/{}-perc-app.out'.format(host))
                p = self.startProcess(command)
                self.perc_apps.append((host, p)) 
            else:
                # this host is not the source of any flows
                start_perc_app = os.path.expandvars('ssh root@{} "$CT_EXP_DIR/exec_at {} {} $MOONGEN_DIR/build/libmoon $MOONGEN_DIR/examples/test_perc_control.lua -n 0 -w {} -c {} -f {} 0 {}" > {}')
                startTime = expStartTime 
                startTime_sec = int(startTime)
                startTime_nsec = int((startTime - int(startTime))*(10**9))
                log_port = '1' if host in LOGGING_IFACES else ''
                command = start_perc_app.format(host, startTime_sec, startTime_nsec, START_DELAY, LOGGING_THREADS, '/tmp/perc-log-{}.pcap'.format(host), log_port, 'logs/{}-perc-app.out'.format(host))
                p = self.startProcess(command)
                self.perc_apps.append((host, p))

        # wait for all flows to complete
        currTime = get_real_time()
        endTime = expStartTime + self.workload.max_flow_dur + START_DELAY + WAIT_TO_KILL
        print "Waiting for all flows to complete ..."
        time.sleep(endTime - currTime)

        # wait for all iperf clients to finish
        for (host, perc_app) in self.perc_apps:
            print "Killing perc_app on host {} ...".format(host)
            perc_app.kill()
            print "perc_app on host {} finished with return code: {}".format(host, perc_app.returncode)

        self.cleanupExperiment()

    # kill all tcpdump logging processes
    # kill all iperf servers
    def cleanupExperiment(self):

#        # kill all tcpdump logging processes
#        for (host, log_process) in self.logging_processes:
#            log_process.kill() 
#            command = 'ssh root@{0} "pkill -u root tcpdump"'.format(host) 
#            rc = self.runCommand(command) 
#            if rc not in [0,1]:
#                print >> sys.stderr, "ERROR: {0} -- failed".format(command)

#        # kill all iperf servers
#        for (host, server) in self.iperf_servers:
#            server.kill() 
#            command = 'ssh root@{0} "pkill -u root iperf3"'.format(host)
#            rc = self.runCommand(command) 
#            if rc not in [0,1]:
#                print >> sys.stderr, "ERROR: {0} -- failed".format(command)             

        # copy log files
        log_dir = os.path.expandvars('$CT_EXP_DIR/logs/')
        copy_log_file = 'scp root@{0}:/tmp/perc-log*{0}.pcap %s' % log_dir
        os.system(os.path.expandvars('rm -rf $CT_EXP_DIR/logs/'))
        os.makedirs(log_dir)
        # copy the log file
        for host in LOGGING_IFACES:
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
        return subprocess.Popen(command, shell=True) 
   
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






