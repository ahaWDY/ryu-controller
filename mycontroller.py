from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.topology.switches import LLDPPacket
import networkx as nx

ARP=arp.arp.__name__
ETHERNET=ethernet.ethernet.__name__
ETHERNET_MULTICAST="ff:ff:ff:ff:ff:ff"


class myswitch13(app_manager.RyuApp):
    #set openflow protocol
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(myswitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {} # mac address table,other network's host's direction
	self.net=nx.DiGraph() # topology
	self.switch2_port={} # switch to switch port
	self.arp_table = {} # received arp_table

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath 
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table miss from switch to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    # add table miss
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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
    
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
	dpid = datapath.id
	
	#parse lldp packet to get topology
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
	    src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
	    dst_dpid, dst_port_no = datapath.id, msg.match['in_port']
	    #add switch to switch link
	    self.net.add_edge(src_dpid,dst_dpid,src_port=src_port_no, dst_port=dst_port_no)
	    
	    #add switch to switch port
	    if self.switch2_port.has_key(dst_dpid):
		self.switch2_port[dst_dpid].add(dst_port_no)
	    else:
		self.switch2_port[dst_dpid] = {dst_port_no}
	    #print "topology update:"
	    #print src_dpid, dst_dpid
	    #print self.net.edges()
            return

        dst = eth.dst
        src = eth.src
	
	#discard the ARP packege received for the second time
	header_list=dict((p.protocol_name, p)for p in pkt.protocols if type(p) != str)
	if dst==ETHERNET_MULTICAST and ARP in header_list:
	    arp_dst_ip=header_list[ARP].dst_ip
	    #this ARP has been recieved before
	    if (dpid,src,arp_dst_ip) in self.arp_table:
		#it comes from a different port this time, discard it
		if self.arp_table[(dpid,src,arp_dst_ip)] != in_port:
		    out=parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=[], data=None)
		    datapath.send_msg(out)
		    return
	    else:
		#record it if it is received for the first time
		self.arp_table[(dpid,src,arp_dst_ip)] = in_port
		
	#record the port which the packet should be transffered to
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
	
	# find the port
	if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

	# Add the link between the host and it's switch	
	if src not in self.net and in_port not in self.switch2_port[dpid]: 
            self.net.add_edge(src,dpid,src_port=-1,dst_port=in_port) 
	    self.net.add_edge(dpid,src,src_port=in_port, dst_port=-1)
	    print "host link added"
	    print src, dpid
	
	# if the destination in the local network, find the shortest path
        if src in self.net and dst in self.net and dpid in self.net:
    	    path=nx.shortest_path(self.net,src,dst) #compute the shortest path
	    if dpid not in path:
		return  
            next=path[path.index(dpid)+1] #get next hop
            out_port=self.net[dpid][next]['src_port'] #get output port
	    self.mac_to_port[dpid][dst] = out_port

	    # arrived in the destination switch, output the path
	    if next==dst and dpid==path[-2]:
		print "path:",src, "->",dst
		print "the length of the path {}".format(len(path))
		print path
		print "\n"

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
