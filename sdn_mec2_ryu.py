from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import in_proto
from ryu import cfg
import time
import sqlite3


class MEController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MEController, self).__init__(*args, **kwargs)
	self.init_db()
        self.cpt = 0
        self.datapaths = {}
        self.bdy = []

        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('IDLE_TIMEOUT'),
            cfg.IntOpt('HARD_TIMEOUT'),
            cfg.StrOpt('MAC_GW'),
            cfg.StrOpt('MAC_MEC'),
            cfg.IntOpt('PORT_GW'),
            cfg.IntOpt('PORT_ENB'),
            cfg.IntOpt('PORT_MEC'),
            cfg.IntOpt('table_0'),
            cfg.IntOpt('table_1')])
        
        self.IDLE_TIMEOUT = CONF.IDLE_TIMEOUT
        self.HARD_TIMEOUT = CONF.HARD_TIMEOUT 
        self.MAC_GW = CONF.MAC_GW 
        self.MAC_MEC = CONF.MAC_MEC 
        self.PORT_GW = CONF.PORT_GW
        self.PORT_ENB = CONF.PORT_ENB 
        self.PORT_MEC = CONF.PORT_MEC
        self.table_0 = CONF.table_0 
        self.table_1 = CONF.table_1
  
    def init_db(self):
        self.db_loc = sqlite3.connect('mecrule.db',check_same_thread=False)
        cursor = self.db_loc.cursor()
        cursor.execute('drop table if exists mecrule')
        cursor.execute('''CREATE TABLE mecrule(
               id INTEGER PRIMARY KEY,
               type TEXT,
               mecip TEXT,
               ueip TEXT,  
               proto TEXT,
               port INTEGER,
               dstip TEXT);''')
        self.db_loc.commit()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # configure the default rules at the switch
	      # frist rule redirect all packets from the UE to the controller
        
        match = parser.OFPMatch(in_port = self.PORT_ENB)
        
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                               ofproto.OFPCML_NO_BUFFER)]
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        self.add_flow(datapath, priority=0, match=match,
                                       inst=inst, table_id=self.table_1)
        

        # second rule redirect traffic from internet to table 1
        
        match = parser.OFPMatch()
        
        inst = [parser.OFPInstructionGotoTable(self.table_1)]
        
        self.add_flow(datapath, priority=0, match=match,
                                       inst=inst, table_id=self.table_0)

    def add_flow(self, datapath, priority, match, inst, table_id, idle=0, hard=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # in case the Packet_IN is for a buffered packet then we send a FLowMod message with its buffer ID
        # else we send it without the buffer ID
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     priority=priority, match=match, instructions=inst,
                                         table_id=table_id, idle_timeout=idle, hard_timeout=hard)
        
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, 
                                                 match=match, instructions=inst, 
                                         table_id=table_id, idle_timeout=idle, hard_timeout=hard)
        
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.logger.info("Packet_IN: %s %s %s %s", dpid, src, dst, in_port)

        cursor = self.db_loc.cursor()
        
        # if the Ethernet frame is of type IP, extract the source IP
        # in case the source IP is in the table of all then a rule will be created
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            srcipp = ip.src
            dstipp = ip.dst
            protocol = ip.proto
            p=""
            prt=""
            self.logger.debug("Protocol %s", protocol)
            if protocol == 6:
                p="TCP"
                tcpp = pkt.get_protocol(tcp.tcp)
                prt = tcpp.dst_port
                print(prt)
            elif protocol == 17:
                p="UDP"
                udpp = pkt.get_protocol(udp.udp)
                prt = udpp.dst_port
                print(prt)
            cursor.execute('''SELECT * FROM mecrule WHERE proto=? AND port=? AND dstip=?;''',(p,prt,dstipp))
            rslt = cursor.fetchone()
	    print(rslt)
            
            if rslt != None:
                if rslt[1] == 'all_tcp': # redirection of tcp traffic having a specific port destination
                    self.logger.debug("Find a rule for a group")
                    
                    match = parser.OFPMatch(in_port=self.PORT_ENB, tcp_dst=rslt[5], ipv4_dst=dstipp,
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
                    
                    actions=[parser.OFPActionSetField(eth_dst=self.MAC_MEC),
                                     parser.OFPActionSetField(ipv4_dst=rslt[2]),
                                                          parser.OFPActionOutput(self.PORT_MEC)]

                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:                      
                                                                           
                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT,
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)
                    
                    else:
                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)

                    # second rule MEC server -> UE. In table 0
                    
                    match = parser.OFPMatch(in_port=self.PORT_MEC, tcp_src=rslt[5], ipv4_src=rslt[2],
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
                    
                    actions=[parser.OFPActionSetField(ipv4_src=dstipp)]
                    
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                                                                      parser.OFPInstructionGotoTable(self.table_1)]
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT,
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)
                    
                    else:
                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)

                elif rslt[1] == 'all_udp':# redirection of udp traffic having a specific port destination
                    self.logger.debug("Find a rule for a group")
                    
                    match = parser.OFPMatch(in_port=self.PORT_ENB, udp_dst=rslt[5], ipv4_dst=dstipp,
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP)
                    
                    actions=[parser.OFPActionSetField(eth_dst=self.MAC_MEC),
                                     parser.OFPActionSetField(ipv4_dst=rslt[2]),
                                                          parser.OFPActionOutput(self.PORT_MEC)]

                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:                      
                                                                           
                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT,
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)
                    
                    else:
                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)

                    # second rule MEC server -> UE. In table 0
                    
                    match = parser.OFPMatch(in_port=self.PORT_MEC, udp_src=rslt[5], ipv4_src=rslt[2],
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP)
                    
                    actions=[parser.OFPActionSetField(ipv4_src=dstipp)]
                    
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                                                                      parser.OFPInstructionGotoTable(self.table_1)]
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT,
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)
                    
                    else:
                        self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)    
                                                   
                elif rslt[1] == '1':
                    cursor.execute('''SELECT * FROM mecrule WHERE proto=? AND port=? AND dstip=? AND ueip=?;''',(p,prt,dstipp,srcipp))
                    rslt = cursor.fetchone()
	            print(rslt)  
                    
                    if rslt != None:
                        if rslt[4]=='TCP': # redirection of tcp traffic for a single user
                            self.logger.debug("Find a rule of type %s", rslt[1])                       
                    
                            match = parser.OFPMatch(in_port=self.PORT_ENB, tcp_dst=rslt[5], ipv4_src=srcipp, ipv4_dst=dstipp,
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
                    
                            actions=[parser.OFPActionSetField(eth_dst=self.MAC_MEC),
                                     parser.OFPActionSetField(ipv4_dst=rslt[2]),
                                                         parser.OFPActionOutput(self.PORT_MEC)]
                            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    
                            if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT, 
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)

                            else:
                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)
                    
                            # second rule MEC server -> UE. In table 0
                    
                            match = parser.OFPMatch(in_port=self.PORT_MEC, tcp_src=rslt[5], ipv4_dst=srcipp,
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_TCP)
                    
                            actions=[parser.OFPActionSetField(ipv4_src=dstipp)]
                    
                            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), 
                                                                parser.OFPInstructionGotoTable(self.table_1)]
                    
                            if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT,
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)
                    

                            else:
                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)                                
                                     
                                                                        
                        elif rslt[4]=='UDP': # redirection of udp traffic for a single user
                    
                            self.logger.debug("Find a rule of type %s", rslt[1])                       
                    
                            match = parser.OFPMatch(in_port=self.PORT_ENB, udp_dst=rslt[5], ipv4_src=srcipp, ipv4_dst=dstipp,
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP)
                    
                            actions=[parser.OFPActionSetField(eth_dst=self.MAC_MEC),
                                     parser.OFPActionSetField(ipv4_dst=rslt[2]),
                                                         parser.OFPActionOutput(self.PORT_MEC)]
                            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    
                            if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT, 
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)

                            else:
                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_1, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)
                    
                            # second rule MEC server -> UE. In table 0
                    
                            match = parser.OFPMatch(in_port=self.PORT_MEC, udp_src=rslt[5], ipv4_dst=srcipp,
                                              eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP)
                    
                            actions=[parser.OFPActionSetField(ipv4_src=dstipp)]
                    
                            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions), 
                                                                parser.OFPInstructionGotoTable(self.table_1)]
                    
                            if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT,
                                                                   hard=self.HARD_TIMEOUT, buffer_id=msg.buffer_id)
                    

                            else:
                                self.add_flow(datapath, priority=40, match=match, inst=inst,
                                                       table_id=self.table_0, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)       
                                                    
                                         
                                         
                    else:                     
                        self.default_path(datapath, self.PORT_ENB, ether_types.ETH_TYPE_IP, dstipp, self.MAC_GW, self.PORT_GW, msg.buffer_id)
                        
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            return                              
          
                else:
                    self.default_path(datapath, self.PORT_ENB, ether_types.ETH_TYPE_IP, dstipp, self.MAC_GW, self.PORT_GW, msg.buffer_id)
                        
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        return      

            else:
                self.default_path(datapath, self.PORT_ENB, ether_types.ETH_TYPE_IP, dstipp, self.MAC_GW, self.PORT_GW, msg.buffer_id)
                        
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    return                                                           
                                                   
                                                        
        # after installing the rules to the switch we need to send packet out
        # of the incoming packet to the appropriate port of the OVS switch
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            protocol = ip.proto
             

            if protocol == in_proto.IPPROTO_TCP:
                t = pkt.get_protocol(tcp.tcp)
                flag=0
                if rslt !=None:

                    if rslt[1]=='all_tcp':
                        flag=1

                    if rslt[1]=='1' and rslt[3]==str(srcipp):
                        flag=1
        
                if flag==1:
                    actions = [parser.OFPActionOutput(self.PORT_MEC)]
                    
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                 in_port=self.PORT_ENB, actions=actions, data=data) 
                    datapath.send_msg(out)
                    print("I am a TCP PACKET OUT to the MEC")

                else:
                    self.pack_out_GW(self.PORT_GW, datapath, msg.buffer_id, self.PORT_ENB, data)

                                                                                                                                                                                                                                                                                                                                              
            elif protocol == in_proto.IPPROTO_UDP:
                u = pkt.get_protocol(udp.udp)
                flag=0
                
                if rslt !=None:

                    if rslt[1]=='all_udp': 
                        flag=1

                    if rslt[1]=='1' and rslt[3]==str(srcipp):
                        flag=1

                if flag==1:
                    actions = [parser.OFPActionOutput(self.PORT_MEC)]
                    
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                                 in_port=self.PORT_ENB, actions=actions, data=data) 
                    datapath.send_msg(out)
                    print("I am a UDP PACKET OUT to the MEC")
                
                else:
                    self.pack_out_GW(self.PORT_GW, datapath, msg.buffer_id, self.PORT_ENB, data)

            else:
                self.pack_out_GW(self.PORT_GW, datapath, msg.buffer_id, self.PORT_ENB, data)

        else:
            self.pack_out_GW(self.PORT_GW, datapath, msg.buffer_id, self.PORT_ENB, data)



    def pack_out_GW(self, port_out, datapath, bufferr, port_in, data):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser 

        actions = [parser.OFPActionOutput(port_out)]
               
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=bufferr,
                                         in_port=port_in, actions=actions, data=data)
 
        datapath.send_msg(out)   

    def default_path(self, datapath, port_in, etherr, dstipv4, MAC_Int, port_out, bufferr):
    
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # create an openflow message to install the default rule for this UE, coming from PORT_ENB
                        
        match = parser.OFPMatch(in_port=port_in, eth_type=etherr, ipv4_dst=dstipv4)
        
        actions=[parser.OFPActionSetField(eth_dst=MAC_Int), parser.OFPActionOutput(port_out)]                       
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # after sending the last FLowMod message, in case it is sent with buffer ID
        # no need to send Packet_OUT message

        if bufferr != ofproto.OFP_NO_BUFFER:
        
            self.add_flow(datapath, priority=10, match=match, inst=inst, 
                                table_id=self.table_1, idle=self.IDLE_TIMEOUT,
                                        hard=self.HARD_TIMEOUT, buffer_id=bufferr)
             
        else:
            self.add_flow(datapath, priority=10, match=match, inst=inst, 
                      table_id=self.table_1, idle=self.IDLE_TIMEOUT, hard=self.HARD_TIMEOUT)
 
