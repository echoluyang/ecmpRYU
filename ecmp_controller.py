from __future__ import division
import copy
from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from collections import defaultdict
from operator import itemgetter
from ryu.controller import mac_to_port
import os
import random
import time
import collections


DEFAULT_BW = 10000000
bw=defaultdict(lambda:defaultdict(lambda:None))

class ECMPController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ECMPController, self).__init__(*args, **kwargs)
        self.name = 'monitor'
        self.datapaths = {}
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.free_bandwidth = {}
        # Start to green thread to monitor traffic and calculating
        # free bandwidth of links respectively.
        self.monitor_thread = hub.spawn(self._monitor)
        self.port_features = collections.defaultdict(dict)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.switches_datapaths = {}
        self.arp_info = {}
        self.switches = []
        self.switch_group_ids = {}
        self.group_ids = []
        self.neighbor = collections.defaultdict(dict)
        self.priority = 10000
        global bw
        try:
            f = open("topo.txt", "r")
            for line in f:
                a=line.split()
                if a:
                    bw[int(a[0])][int(a[1])]=int(a[2])
                    bw[int(a[1])][int(a[0])]=int(a[2])
            f.close()
        except IOError:
          print "topo.txt ready"


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Record datapath's info
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        """
            Main entry method of monitoring traffic.
        """
        while 1:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)



    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)



    def _cal_free_bw(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        # capacity: Mbps speed: Bps
        if port_no not in self.port_features[dpid]:
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = DEFAULT_BW
        elif self.port_features[dpid][port_no]:
            capacity = self.port_features[dpid][port_no]
            curr_bw = max(capacity - speed * 8/10**6, 0)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
            #self.logger.info('Current Free Bandwidth For %03x \'s port %03x: %015f', dpid, port_no, curr_bw)
        else:
            self.logger.info("Fail in getting port state")

    def _save_dict(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.free_bandwidth.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_dict(self.port_stats, key, value, 5)
                period = 10
                st = self.port_stats[key]
                if len(st) > 1:
                    now = st[-1][3] + st[-1][4] / (10**9)
                    prev = st[-2][3] + st[-2][4] / (10**9)
                    period = now - prev #sec

                tot = self.port_stats[key][-1][0] + self.port_stats[key][-1][1]
                speed = tot/period
                self._save_dict(self.port_speed, key, speed, 5)
                self._cal_free_bw(dpid, port_no, speed)

#multipath
	# generate neighbor switches and port used
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        self.neighbor[src.dpid][dst.dpid] = src.port_no
        self.neighbor[dst.dpid][src.dpid] = dst.port_no
        self.port_features[src.dpid][src.port_no] = bw[src.dpid][dst.dpid]

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.neighbor[src.dpid][dst.dpid]
            del self.neighbor[dst.dpid][src.dpid]
        except KeyError:
            pass

    # recored all switches used in topo
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch_dp = ev.switch.dp
        parser = switch_dp.ofproto_parser

        if switch_dp.id not in self.switches:
            self.switches.append(switch_dp.id)
            self.switches_datapaths[switch_dp.id] = switch_dp


    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        switch_dp = ev.switch.dp
        switch_id = switch_dp.id
        if switch_id in self.switches:
            del self.switches_datapaths[switch_id]
            del self.neighbor[switch_id]
            self.switches.remove(switch_id)


    # register switches
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print "switch ", dpid, "connected"
            

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # find all avaliable paths from source to destination
    def find_all_paths(self,src,dst):
    	graph = defaultdict(list)
    	for key, value in self.neighbor.items():
    		u = key
    		node = value.keys()
    		for v in node:
    			graph[u].append(v)

    	if src == dst:
    		return [[src]]
    	paths = []
    	visited  = [False] * 100
    	path = []

    	def printAllPaths(u,d,visited,path,paths):
			visited[u] = True
			path.append(u)
			if u == d:
				#print path
				paths.append(path[:])
			else:
				for i in graph[u]:
					if visited[i] == False:
						printAllPaths(i, d, visited, path, paths)
			path.pop()
			visited[u] = False
			

    	printAllPaths(src, dst, visited, path, paths)
    	print "Available paths ", paths
    	#print "Available paths from ", src "to dst ", dst, paths
    	return paths

    # based on hops cost metic, calculate path cost
    def calculate_path_cost(self, path):
        # get [path cost
        # use hub count as link cost, each link cost is 1
        cost = 0
        for i in range(len(path) - 1):
            cost += 1
        return cost

    # find the shortes cost paths from src to dst
    def find_optimal_paths(self, src, dst):
        # get the shortest paths
        #paths = self.get_paths(src, dst)
        paths = self.find_all_paths(src,dst)
        mn = 100
        p = []
        for i in paths:
            cost = self.calculate_path_cost(i)
            if cost < mn:
                mn = cost
                p = [i]
            elif cost == mn:
                p.append(i)
        return p

    # generate a random group id
    def random_group_id(self):
        n = random.randint(0, 2**8)
        while n in self.group_ids:
            n = random.randint(0, 2**8)
        self.group_ids.append(n)
        return n

    # get bandwidth bwtween each link
    def get_bw_link_cost(self,s1,s2):
        e1 = self.neighbor[s1][s2]
        e2 = self.neighbor[s2][s1]
        if self.free_bandwidth[s1][e1] == 0:
            self.free_bandwidth[s1][e1] = DEFAULT_BW
            self.logger.debug("node overloaded")
        if self.free_bandwidth[s2][e2] == 0:
            self.free_bandwidth[s2][e2] = DEFAULT_BW
            self.logger.debug("node overloaded")
        bl = min(self.free_bandwidth[s1][e1], self.free_bandwidth[s2][e2])    
        return bl

    # get the minimum bandwidth for each path, and that bw is the path bw
    def get_bw_path_cost(self, path):
        cost = []
        for i in range(len(path)-1):
        	tmp = self.get_bw_link_cost(path[i], path[i+1])
        	cost.append(tmp)
        return min(cost)


    # main logic of the controller, determine all optimal paths and create group table
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet got turncated")

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            # avoid broadcast from LLDP packet
            return

        # if is IPV6 packets, drop it
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        if isinstance(ipv6_pkt, ipv6.ipv6):
          
            match = parser.OFPMatch(eth_type=eth_pkt.ethertype)
            actions = []
            # send to controller
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth_pkt.dst
        src = eth_pkt.src
        dpid = datapath.id
        print "packet in dpid, src, dst, in_port are", dpid, src, dst, in_port
        
        # learn mac address to avoid flood
        if src not in self.mac_to_port:
            self.mac_to_port[src] = [dpid, in_port]

        # if dst mac address is not learned, flood the request
        if dst in self.mac_to_port:
            out_port = self.mac_to_port[dst][1]
        else:
            out_port = ofproto.OFPP_FLOOD

        # if is ipv4 (arp) packet, do not flood, create group table
        if isinstance(arp_pkt, arp.arp):
        	out_port = self._handle_arp(arp_pkt, src, dst, out_port)
        
        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def generate_group_mod(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.find_optimal_paths(src, dst)
        
        path_cost = []
        for path in paths:
            path_cost.append(self.calculate_path_cost(path))
            print "path is : ", path, "    path cost is : ", path_cost[-1]
        
        bw_cost = []
        for path in paths:
        	bw_cost.append(self.get_bw_path_cost(path))
        	print "path is : ", path, "    bandwidth is : ", bw_cost[-1]
            #print("path is :", path, "    bandwidth is : ", bw_cost[-1])	

        #for each optimal paths, get the port number connectiing two switches
        paths_with_ports = self.switch_with_pid_for_path(paths, first_port, last_port)
        #print "paths_with_ports", paths_with_ports
        used_switches = set().union(*paths)

        for sw_id in used_switches:
            dp = self.switches_datapaths[sw_id]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser
            ports = self.go_through_port(sw_id, paths_with_ports, bw_cost)

            actions = []
         
            for in_port in ports:
                match_ip = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_src, ipv4_dst=ip_dst)
               
                match_arp = ofp_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_spa=ip_src, arp_tpa=ip_dst)
 
                out_ports = ports[in_port]
                # print out_ports 
                # if ports number > 2, create group table, otherwise, all flows are send to one out_port
                if len(out_ports) > 1:
                    group_id = None
                    combine_flow = False
                    group_new = False

                    # check to see if need to create group table
                    whether_group = self.if_need_group_table(sw_id,src,dst)
                    #print "whether_group is ", whether_group
                    if whether_group is not None:
                        
                    	group_new = whether_group[0]
                    if whether_group is not None:
						combine_flow = whether_group[1]
                    group_id = self.switch_group_ids[sw_id, src, dst]
                    buckets = self.generate_group_table(out_ports, group_new, dp)

                    #print "group buckets is ", buckets
                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                        actions = [ofp_parser.OFPActionGroup(group_id)]
                        self.add_flow(dp, self.priority, match_ip, actions)
                    	self.add_flow(dp, 1, match_arp, actions)
                    
                    elif group_new == False and combine_flow == False:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)
                    	actions = [ofp_parser.OFPActionGroup(group_id)]
                    	self.add_flow(dp, self.priority, match_ip, actions)
                    	self.add_flow(dp, 1, match_arp, actions)

                   	# if a swith has a group table, but out port is the port connected to host, we combine all
                   	# flows and send it
                    #if combine_flow == True and group_new == False:
                    elif combine_flow == True and group_new == False:
                    	actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]
                    	self.add_flow(dp, self.priority, match_ip, actions)
                    	self.add_flow(dp, 1, match_arp, actions)
                    	

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, self.priority, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)


        print "Path installation finished in ", time.time() - computation_start 
        return paths_with_ports[0][src][1]

    def generate_group_table(self, out_ports, if_new_group, dp):
     	ofp = dp.ofproto
     	parser = dp.ofproto_parser
        bucket_total = 0
        all_weights = []
        buckets = []

        tot = 0
        for port, weight in out_ports:
            tot += weight

        for port, weight in out_ports:  
            bucket_weight = int(round(float(weight)/float(tot)*100))
            #print "port is :", port, "weight is :", bucket_weight
            all_weights.append(bucket_weight)
            bucket_total += bucket_weight

        i = 0
        while i < len(all_weights) and bucket_total > 100:
        	all_weights[i] -= 1
        	bucket_total -= 1
        	i += 1
        
        dummy = {}

        #print "out_ports", out_ports
        #print "all weight", all_weights
        for i in range(len(out_ports)):
            if out_ports[i][0] not in dummy.keys():
                dummy[out_ports[i][0]] = all_weights[i]
            else:
                dummy[out_ports[i][0]] += all_weights[i]

        #print "dummy", dummy
    
        for port in dummy.keys():

        	weight = dummy[port]

        	bucket_action = [parser.OFPActionOutput(port)]

        	buckets.append(parser.OFPBucket(weight=weight, watch_port=port, watch_group=ofp.OFPG_ANY, actions=bucket_action))
            
       	return buckets

    def if_need_group_table(self, switch, src, dst):
    	if_new_group = False
    	combine_flow = False
        ans = []
        #print "switch, src, dst", switch, src, dst
        #print "switch_group_ids ", self.switch_group_ids
    	if (switch, src, dst) not in self.switch_group_ids:
    		if_new_group = True
    		self.switch_group_ids[switch, src, dst] = self.random_group_id()
    		if src != dst:
    			if switch == dst:
    				if_new_group = False
    				combine_flow = True
        else:
            if switch == dst:
                combine_flow = True

        return [if_new_group , combine_flow]      



	# find the port the path uses
    def go_through_port(self, switch_id, paths_with_ports, path_bw):
    	all_ports = defaultdict(list)
    	i = 0
    	for path in paths_with_ports:
    		if switch_id in path:
    			src_port = path[switch_id][0]
    			dst_port = path[switch_id][1]
    			if (dst_port, path_bw[i]) not in all_ports[src_port]:
    				all_ports[src_port].append((dst_port, path_bw[i]))
    		i += 1
    	return all_ports


    # for each path, get all switches used and all ports connected with switches
    # eg : 8:[4,3]
    def switch_with_pid_for_path(self,paths,src_port,dst_port):
        ans = []
        #print "neighbor", self.neighbor
        for path in paths:
            cur_path = collections.defaultdict(list)
            port_in = src_port
            for i in range(len(path)-1):
                cur_switch = path[i]
                next_switch = path[i+1]
                port_out = self.neighbor[cur_switch][next_switch]
                cur_path[cur_switch] = [port_in, port_out]
                port_in = self.neighbor[next_switch][cur_switch]
            cur_path[next_switch] = [port_in, dst_port]
            ans.append(cur_path)
        return ans


    # handle ipv4 arp for ethernet
    def _handle_arp(self, pkt_arp, src_mac, dst_mac,out_port):
    	# ma_to_port : {mac_add:[port1, port2]}
    	src_ip = pkt_arp.src_ip
    	dst_ip = pkt_arp.dst_ip

    	if pkt_arp.opcode == arp.ARP_REQUEST:
    		if dst_ip in self.arp_info:
    			self.arp_info[src_ip] = src_mac
    			dst_mac = self.arp_info[dst_ip]
    			src_switch_port = self.mac_to_port[src_mac]
    			dst_switch_port = self.mac_to_port[dst_mac]
    			src_switch = src_switch_port[0]
    			src_port = src_switch_port[1]
    			dst_switch = dst_switch_port[0]
    			dst_port = dst_switch_port[1]
    			out_port = self.generate_group_mod(src_switch, src_port, dst_switch, dst_port, src_ip, dst_ip)
    			self.generate_group_mod(src_switch,src_port,dst_switch,dst_port,src_ip, dst_ip)
				
        elif pkt_arp.opcode == arp.ARP_REPLY:
            self.arp_info[src_ip] = src_mac
            src_switch_port = self.mac_to_port[src_mac]
            dst_switch_port = self.mac_to_port[dst_mac]
            src_switch = src_switch_port[0]
            src_port = src_switch_port[1]
            dst_switch = dst_switch_port[0]
            dst_port = dst_switch_port[1]
            out_port = self.generate_group_mod(src_switch, src_port, dst_switch, dst_port, src_ip, dst_ip)
            self.generate_group_mod(src_switch, src_port, dst_switch, dst_port, src_ip, dst_ip)

        return out_port
    		
