
"""
This parses the input flows.txt file into a Workload
object that is used by other parts of the infrastructure
to setup and run the experiments
"""

import sys, os, re
from ip_info import ip_info

class Workload:
    
    def __init__(self, flowsFile):
        self.flowsFile = flowsFile
        self.numLinksFormat = r'num_links: ([\d]*)'
        self.linkCapFormat = r'link_capacities \(Gbps\): ([\d]*)'
        self.flowFormat = r'(?P<startTime>[ \d\.]*),(?P<duration>[ \d]*),(?P<numConn>[ \d]*): (?P<srcIP>[\d\.]*),[ ]*(?P<dstIP>[\d\.]*) -> (?P<links>[ \d,]*)'
        self.ip_info = ip_info 
        
        # self.flows is a list with entries of the form: 
        #   {'srcIP':'xx.xx.xx.xx', 'dstIP':'yy.yy.yy.yy', 'port':num, 'links':[x, y, z], 'srcHost':h1, 'dstHost':h2}
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
        self.max_flow_dur = 0
    
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
        allHosts = list(set([self.ip_info[IP]['hostname'] for IP in self.allIPs]))
        self.srcHosts = list(set([self.ip_info[IP]['hostname'] for IP in self.srcs]))
        self.dstHosts = list(set([self.ip_info[IP]['hostname'] for IP in self.dsts]))
        self.numFlows = len(self.flows)
        offset_id = 1
        for i, flow in zip(range(len(self.flows)), self.flows):
            flow['offset_id'] = offset_id
            flow['links'] = map(int, flow['links'].split(','))
            flow['srcHost'] = self.ip_info[flow['srcIP']]['hostname']
            flow['dstHost'] = self.ip_info[flow['dstIP']]['hostname']
            flow['startTime'] = float(flow['startTime'])
            numConn = int(flow['numConn'])
            flow['numConn'] = numConn
            offset_id += numConn 
            dur = int(flow['duration'])
            flow['duration'] = dur
            self.max_flow_dur = dur if (dur > self.max_flow_dur) else self.max_flow_dur 

        self.allHosts = {}
        for host in allHosts:
            host_dict = {}
            if host in self.srcHosts:
                host_flows = [flow for flow in self.flows if flow['srcHost'] == host]
                assert(len(host_flows) == 1)
                host_dict['flow'] = host_flows[0] # only support one "flow" per host for now
            else:
                host_dict['flow'] = None
            self.allHosts[host] = host_dict

