
"""
This class computes the idea rates for a given workload
"""

import sys
import random
import matplotlib.pyplot as plt
import numpy as np
import time

from workload import Workload

class MPMaxMin:
    def __init__(self, workload):        
        
        self.num_flows = workload.numFlows
        self.num_links = workload.numLinks

        self.routes = self.makeIncidenceMatrix(workload) # incidence matrix for flows / links
        self.c = workload.linkCap*np.ones((self.num_links,1), dtype=float) # link capacities
        ################################################################
        # max-min rates
        self.maxmin_level = -1
        self.maxmin_x = self.water_filling()

    def makeIncidenceMatrix(self, workload):
        A = np.zeros((self.num_flows, self.num_links))
        for flowID, flow in zip(range(self.num_flows), workload.flows):
            A[flowID, flow['links']] = 1
        return A
                      
    def water_filling(self): 
        weights = np.ones((self.num_flows, 1), dtype=float)
        x = np.zeros((self.num_flows,1), dtype=float)
        rem_flows = np.array(range(self.num_flows))
        rem_cap = np.array(self.c, copy=True)
        level = 0
        while rem_flows.size != 0:
            level += 1
            link_weights = self.routes.T.dot(weights)
            with np.errstate(divide='ignore', invalid='ignore'):
                bl = np.argmax(np.where(link_weights>0.0, link_weights/rem_cap, -1))
            inc = rem_cap[bl]/link_weights[bl]
            x[rem_flows] = x[rem_flows] + inc*weights[rem_flows]                
            rem_cap = rem_cap - inc*link_weights
            rem_cap = np.where(rem_cap>0.0, rem_cap, 0.0)       
            bf = np.nonzero(self.routes[:,bl])[0]
            rem_bf = np.array([f for f in rem_flows if f in bf])
            print "level ", level, " bottleneck link is ", bl,\
                ", bottleneck flow has rate ", x[rem_bf[0]]

            rem_flows = np.array([f for f in rem_flows if f not in bf])
            weights[bf] = 0
        self.maxmin_level = level
        print("finished waterfilling")
        return x
                                                                           

