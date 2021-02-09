from collections import defaultdict
from itertools import permutations

import networkx as nx
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event

import ryu.topology.switches as myswitch

ARP = arp.arp.__name__
ETHERNET = ethernet.ethernet.__name__
ETHERNET_MULTICAST = "ff:ff:ff:ff:ff:ff"
DELETE_SWITCH = "delete_switch"
TOPO_UPDATE_INFO = 2333
OFPPR_DELETE = 1


class myswitch13(app_manager.RyuApp):
    # set openflow protocol
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(myswitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # mac address table,other network's host's direction
        self.net = nx.DiGraph()  # topology
        self.arp_table = {}  # received arp_table
        self.switches = []  # switches under control
        self.port_to_switch = defaultdict(dict)  # record the port which connects a switch

    # install flow entry
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

    # delete all the flow entries except table miss entry of a switch according to datapath
    def delete_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if datapath.id not in self.mac_to_port.keys():
            return

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    # updte all the flow entries of a switch according to datapath
    def update_flow(self, datapath, msg):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # clear the table first
        self.delete_flow(datapath)
        # find all the alive hosts connected to the switch
        alive_hosts = []
        for node in self.net.nodes:
            if type(node) == str:
                alive_hosts.append(node)
        # enumerate all the links between hosts
        links = permutations(alive_hosts, 2)
        for link in links:
            src = link[0]
            dst = link[1]
            try:
                # find the shortest path
                path = nx.shortest_path(self.net, src, dst)
                if dpid not in path:
                    continue
                previous = path[path.index(dpid) - 1]
                next = path[path.index(dpid) + 1]
                in_port = self.net[previous][dpid]["dst_port"]
                out_port = self.net[dpid][next]["src_port"]
                self.mac_to_port[dpid][dst] = out_port
                actions = [parser.OFPActionOutput(out_port)]
                # install a flow
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                    self.add_flow(datapath, 1, match, actions)
            except Exception as e:
                print e
                pass

    # function used to send lldp packet

    def send_lldp(self, send_port, src_dpid, src_port, switch, topology=None):
        # construct lldp packet according to given information
        if not topology:
            lldp_data = myswitch.LLDPPacket.lldp_packet(src_dpid, src_port, 1, 1)
        else:
            lldp_data = myswitch.LLDPPacket.lldp_packet(src_dpid, src_port, 1, 1, topology)

        actions = [switch.ofproto_parser.OFPActionOutput(send_port)]
        out = switch.ofproto_parser.OFPPacketOut(
            datapath=switch, in_port=switch.ofproto.OFPP_CONTROLLER,
            buffer_id=switch.ofproto.OFP_NO_BUFFER, actions=actions,
            data=lldp_data)
        switch.send_msg(out)

    # handle reveived lldp packet
    def lldp_handler(self, msg, datapath):
        flag = False  # mark whether topology is updated
        infos = myswitch.LLDPPacket.lldp_parse(msg.data)
        src_dpid, src_port_no = infos[0], infos[1]

        # deal with topology in lldp packet
        if len(infos) == 3:
            # deal with delete
            if infos[2].tlv_info == DELETE_SWITCH:
                if self.net.has_node(src_dpid):
                    # delete the node from topology
                    self.net.remove_node(src_dpid)
                    print "delete node ", src_dpid, "current topo", self.net.edges, " current nodes ", self.net.nodes
                    # flood the lldp package to other network
                    for switch in self.switches:
                        for port in switch.ports.keys():
                            self.send_lldp(port, src_dpid, TOPO_UPDATE_INFO, switch, DELETE_SWITCH)
                # update the table
                self.update_flow(datapath, msg)
                return
            # update the topo according to the topology in lldp packet
            else:
                src_topo = infos[2].tlv_info.split("+")
                for edge in src_topo:
                    nodes = edge.split(',')
                    in_node = eval(nodes[0][1:])
                    out_node = eval(nodes[1][1:-1])
                    if not self.net.has_edge(in_node, out_node):
                        self.net.add_edge(in_node, out_node)
                        self.net.add_edge(out_node, in_node)
                        flag = True
                    # update flow if add new host to topology
                    if type(in_node) == str or type(out_node) == str:
                        self.update_flow(datapath, msg)

        # new switch come to network
        if src_port_no != TOPO_UPDATE_INFO:
            dst_dpid, dst_port_no = datapath.id, msg.match['in_port']
            # add switch to switch link
            if not self.net.has_edge(src_dpid, dst_dpid):
                flag = True
            self.net.add_edge(src_dpid, dst_dpid, src_port=src_port_no, dst_port=dst_port_no)
            self.net.add_edge(dst_dpid, src_dpid, src_port=dst_port_no, dst_port=src_port_no)

            # record the port and its connected switch
            self.port_to_switch[dst_dpid][dst_port_no] = src_dpid
            self.port_to_switch[src_dpid][src_port_no] = dst_dpid

            print "add new edges normal", src_dpid, dst_dpid, src_port_no, dst_port_no, self.net.edges

        # send lldp packet with topology if topology updated
        if flag:
            # update flow table
            # self.update_flow(datapath, msg)
            topology = "+".join(str(edge) for edge in list(self.net.edges))
            # print "add new edges", self.net.edges
            for switch in self.switches:
                for port in switch.ports.keys():
                    self.send_lldp(port, switch.id, port, switch, topology)
                    #self.send_lldp(port, switch.id, TOPO_UPDATE_INFO, switch, topology)

    # handle received arp packet
    def arp_handler(self, datapath, dpid, eth, in_port, msg, ofproto, parser, pkt):
        dst = eth.dst
        src = eth.src
        # discard the ARP packege received for the second time
        header_list = dict((p.protocol_name, p) for p in pkt.protocols if type(p) != str)
        if dst == ETHERNET_MULTICAST and ARP in header_list:
            arp_dst_ip = header_list[ARP].dst_ip
            # this ARP has been recieved before
            if (dpid, src, arp_dst_ip) in self.arp_table:
                # it comes from a different port this time, discard it
                if self.arp_table[(dpid, src, arp_dst_ip)] != in_port:
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=in_port, actions=[], data=None)
                    datapath.send_msg(out)
                    return
            else:
                # record it if it is received for the first time
                self.arp_table[(dpid, src, arp_dst_ip)] = in_port
        # record the port which the packet should be transffered to
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
        if src not in self.net and in_port not in self.port_to_switch[dpid].keys():
            self.net.add_edge(src, dpid, src_port=-1, dst_port=in_port)
            self.net.add_edge(dpid, src, src_port=in_port, dst_port=-1)
            print "host link added"
            print src, dpid
            print "add new host", self.net.edges
            topology = "+".join(str(edge) for edge in list(self.net.edges))

            print "send new topo", topology
            # self.send_lldp(ofproto.OFPP_FLOOD, dpid, TOPO_UPDATE_INFO, datapath, topology)
            for switch in self.switches:
                for port in switch.ports.keys():
                    self.send_lldp(port, switch.id, TOPO_UPDATE_INFO, switch, topology)

        # if the destination in the local network, find the shortest path
        if src in self.net and dst in self.net and dpid in self.net:
            path = nx.shortest_path(self.net, src, dst)  # compute the shortest path
            if dpid not in path:
                return
            next = path[path.index(dpid) + 1]
            print "dpid and next ", dpid, next  # get next hop
            out_port = self.net[dpid][next]['src_port']  # get output port
            self.mac_to_port[dpid][dst] = out_port

            # arrived in the destination switch, output the path
            if next == dst and dpid == path[-2]:
                print "path:", src, "->", dst
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

    @set_ev_cls(event.EventSwitchEnter, CONFIG_DISPATCHER)
    def _switch_enter_handler(self, ev):
        datapath = ev.switch.dp
        self.switches.append(datapath)

        for port in datapath.ports.keys():
            self.send_lldp(port, datapath.id, port, datapath)

    @set_ev_cls(event.EventSwitchLeave, DEAD_DISPATCHER)
    def _switch_leave_handler(self, ev):
        datapath = ev.switch.dp
        self.switches.remove(datapath)

    @set_ev_cls(ofp_event.EventOFPPortStateChange, CONFIG_DISPATCHER)
    def e_o_p_c(self, ev):
        pass

    @set_ev_cls(ofp_event.EventOFPStateChange, CONFIG_DISPATCHER)
    def e_o_p_c(self, ev):
        pass

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        dp = ev.msg.datapath.id
        reason = ev.msg.reason
        if reason == OFPPR_DELETE:  #
            leave_port = ev.msg.desc.port_no
            leave_switch = self.port_to_switch[dp][leave_port]
            # self.delete_flow(ev.msg.datapath,leave_switch)

            if self.net.has_node(leave_switch):
                self.net.remove_node(leave_switch)
                print "delete node ", leave_switch, "current topo", self.net.edges, " current nodes ", self.net.nodes

            for switch in self.switches:
                for port in switch.ports.keys():
                    self.send_lldp(port, leave_switch, TOPO_UPDATE_INFO, switch, DELETE_SWITCH)
            self.update_flow(ev.msg.datapath, ev.msg)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install flow entry from switch to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(event.EventHostAdd, CONFIG_DISPATCHER)
    def _host_add_handler(self, ev):
        pass

    @set_ev_cls(event.EventHostDelete, CONFIG_DISPATCHER)
    def _host_delete_handler(self, ev):
        datapath = ev.switch.dp
        pass

    @set_ev_cls(event.EventLinkAdd, CONFIG_DISPATCHER)
    def _link_add_handler(self, ev):
        pass

    @set_ev_cls(event.EventLinkDelete, CONFIG_DISPATCHER)
    def _link_delete_handler(self, ev):
        pass

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        if datapath not in self.switches:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id

        # parse lldp packet to get topology
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            self.lldp_handler(msg, datapath)

        else:
            self.arp_handler(datapath, dpid, eth, in_port, msg, ofproto, parser, pkt)
