# ecmpRYU
ecmp load balancing 

RYU is a component-based software defined networking framework. Ryu provides software components with well defined API that make it easy for developers to create new network management and control applications. Thus, Ryu will be a good tool to develop an application that implements ECMP. OpenFlow 1.3 is used as the network communication protocol in this project.

The network infrastructure was constructed using the Mininet network emulator. To implement ECMP, the first thing to do is to define a cost metric. The cost metric is defined as the number of hops used. For example, path 1->2->3 uses 3 hops, thus each link’s cost is 1, and the path cost is 2.

In OpenFlow 1.3, OpenFlow groups were introduced as a way to perform complex operations on packets. Each group contains a bucket list. A bucket contains separate lists of parameters and actions. Depending on group types (ALL, SELECT, INDIRECT), when packets enter the network, each bucket or multiple buckets can be applied to the packets.
