#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf, TCLink
from mininet.topo import Topo
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication
import logging
import os
 
 
def multiControllerNet():
	"Create a network from semi-scratch with multiple controllers."
	
	net = Mininet(controller=RemoteController, switch=OVSSwitch)
	
	print("*** Creating switches")
	s1 = net.addSwitch("s1")
	s2 = net.addSwitch("s2")
	s3 = net.addSwitch("s3")
	s4 = net.addSwitch("s4")
	# s5 = net.addSwitch("s5")
	# s6 = net.addSwitch("s6")
	print("*** Creating hosts")

	h1 = net.addHost("h1",mac="00:00:00:00:00:01",ip="192.168.1.1/16")
	h2 = net.addHost("h2",mac="00:00:00:00:00:02",ip="192.168.1.2/16")
	h3 = net.addHost("h3",mac="00:00:00:00:00:03",ip="192.168.1.3/16")
	h4 = net.addHost("h4",mac="00:00:00:00:00:04",ip="192.168.1.4/16")
	h5 = net.addHost("h5",mac="00:00:00:00:00:05",ip="192.168.1.5/16")
	h6 = net.addHost("h6",mac="00:00:00:00:00:06",ip="192.168.1.6/16")
	h7 = net.addHost("h7",mac="00:00:00:00:00:07",ip="192.168.1.7/16")
	h8 = net.addHost("h8",mac="00:00:00:00:00:08",ip="192.168.1.8/16")

	c1 = net.addController("c1",controller=RemoteController,ip="127.0.0.1",port=6661)
	c2 = net.addController("c2",controller=RemoteController,ip="127.0.0.1",port=6662)
	c3 = net.addController("c3",controller=RemoteController,ip="127.0.0.1",port=6663)
	
	print("*** Creating links of host2switch.")
	
	net.addLink(s1, h1)
	net.addLink(s1, h2)
	net.addLink(s2, h3)
	net.addLink(s2, h4)
	net.addLink(s3, h5)
	net.addLink(s3, h6)
	net.addLink(s4, h7)
	net.addLink(s4, h8)

	
	# print("*** Creating interior links of switch2switch.")
	# net.addLink(s1, s2)
	# net.addLink(s3, s4)
	# net.addLink(s4, s1)

	print("*** Creating intra links of switch2switch.")
	net.addLink(s1, s2)
	net.addLink(s2, s3)
	net.addLink(s3, s4)
	net.addLink(s4, s1)
	#net.addLink(s3, s5)
	#net.addLink(s1, s2)
	#net.addLink(s2, s3)
	#net.addLink(s1, s3)
	print("*** Starting network")
	
	net.build()
	c1.start()
	c2.start()
	c3.start()
	
	
	s1.start([c1])
	s2.start([c1])
	s3.start([c2])
	s4.start([c3])
	# s5.start([c3])
	# s6.start([c3])
	# print "*** Testing network"
	# net.pingAll()
	
	print("*** Running CLI")
	
	CLI(net)
	
	print("*** Stopping network")
	
	net.stop()
 
 
if __name__ == '__main__':
	setLogLevel('info')  # for CLI output
	multiControllerNet()