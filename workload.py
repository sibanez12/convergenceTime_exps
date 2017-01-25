
"""
This parses the input flows.csv file into a Workload
object that is used by other parts of the infrastructure
to setup and run the experiments
"""

import sys, os, re

class Workload:
    
    def __init__(self, flowsFile):
        self.numLinksFormat = r'num_links: ([\d]*)'
        self.linkCapFormat = r'link_capacities \(Gbps\): ([\d]*)'
        self.flowFormat = r'(?P<srcIP>[\d\.]*),[ ]*(?P<dstIP>[\d\.]*) -> (?P<links>[ \d,]*)'
        #self.ipHostMap = {'10.0.0.1':'han-1', '10.0.0.2':'han-2', '10.0.0.3':'han-3', '10.0.0.4':'han-4', '10.0.0.5':'han-5'}
        self.ipHostMap = {'172.24.74.67':'netfpga2', '171.64.74.24':'nf3-test9'}
        
        # self.flows is a list with entries of the form: 
        #   {'srcIP':'xx.xx.xx.xx', 'dstIP':'yy.yy.yy.yy'}
        self.flows = []
        self.numLinks = None
        self.linkCap = None
        self.numFlows = None
        self.srcs = None
        self.dsts = None
        self.allIPs = None
        self.allHosts = None
        self.srcHosts = None
        self.dstHosts = None
    
        # parse the flowsFile
        with open(flowsFile) as f:
            doc = f.read()
            # set self.num_links
            searchObj = re.search(self.numLinksFormat, doc)
            if searchObj is not None:
                self.numLinks = int(searchObj.group(1))
            else:
                print >> sys.stderr, "ERROR: num_links not specified in flowsFile"
                sys.exit(1)

            # set self.link_capacities
            searchObj = re.search(self.linkCapFormat, doc)
            if searchObj is not None:
                self.linkCap = int(searchObj.group(1))
            else:
                print >> sys.stderr, "ERROR: link_capacities not specified in flowsFile"
                sys.exit(1)

            #  set self.flows        
            searchObj = re.search(self.flowFormat, doc)
            while searchObj is not None:
                self.flows.append(searchObj.groupdict())
                doc = doc[:searchObj.start()] + doc[searchObj.end():]
                searchObj = re.search(self.flowFormat, doc)

        self.srcs = [flow['srcIP'] for flow in self.flows]
        self.dsts = [flow['dstIP'] for flow in self.flows]
        self.allIPs = self.srcs + list(set(self.dsts) - set(self.srcs))
        self.allHosts = list(set([self.ipHostMap[IP] for IP in self.allIPs]))
        self.srcHosts = list(set([self.ipHostMap[IP] for IP in self.srcs]))
        self.dstHosts = list(set([self.ipHostMap[IP] for IP in self.dsts]))
        self.numFlows = len(self.flows)
        for flow in self.flows:
            flow['links'] = map(int, flow['links'].split(','))


