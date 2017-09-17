#!/usr/bin/env python

"""
This script runs the convergence time hardware experiments for
TCP and PERC.

The input is a flows.csv that contains entries with the format:
src_ip, dst_ip
Each entry in the flows.csv indicates one flow in the experiment.

This script performs the following functions:
1.) Detemines workload from flows.csv
2.) Runs rate monitoring service on each machine
3.) Distributes global time to start workload and starts workload
4.) After experiment, copies all log files to single location
5.) Computes correct flow rates for given topology and workload
6.) Analyzes log files to determine convergence time of each flow
7.) Reports results

Specifically for for the TCP experiment:
1.) Loads the tcp_probe kernel module on each machine
    - directs the output to a tcp_probe.log file
2.) Starts an iperf server on each machine that will receive a flow
3.) Determines the global time (Tstart) that all of the iperf
    clients should be started and distributes that time to each
    machine.
4.) Tells Tstart to each source machine which then runs a thread that
    sleeps until Tstart and then runs iperf.
5.) Experiment ends after all iperf clients finish.
6.) Copies all of the log files to a single location
7.) Computes the correct rates for each flow using Lavanya's 
    convergence time simulator tool
8.) Analyzes the tcp_probe.log files to determine the convergence time
    of each flow
9.) Reports results

"""

import argparse
from workload import Workload
from ct_experiment_iperf import CT_Experiment

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', action='store_true', default=False, help='configure the host interfaces by adding the necessary routes and populating the ARP tables')
    parser.add_argument('--tcp', type=str, default='dctcp', help='version of tcp to use')
    parser.add_argument('flowsFile', type=str, help="the txt file that contains the flows to run in the experiment")
    args = parser.parse_args()

    workload = Workload(args.flowsFile)

    # starts the rate monitor on each host
    # starts iperf server on each destination machine
    exp = CT_Experiment(workload, args.config)
    
    # get the global start time, distributed to each of the
    # required hosts, and run the experiment 
    exp.runExperiment(args.tcp)

#    # copy all log files to a single location, parse the
#    # results to determine the convergence times
#    results = exp.getResults()

#    exp.reportResults()

if __name__ == "__main__":
    main()

