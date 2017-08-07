
This repo implements a python framework for running convergence
time experiments on network congestion control algorithms.

Usage:

* flows.txt file specifies the workload

$ ./run_ct_exp.py flows.txt

Setup:

1. Source the settings.sh file

2. Add ssh key to root user on all machines

3. Ensure PTP is synchronizing the system clock of the machines

4. Add ipHostMap.py file which maps IP addresses to the host names on which they reside

