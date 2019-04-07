import json
import sqlite3
import sdn_mec2_ryu
from webob import Response
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import time

mec_redirection_instance_name = 'mec_redirection_api_app'
url = '/of/call'

class MEControllerRest(sdn_mec2_ryu.MEController):

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(MEControllerRest, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(MEControllerController,
                      {mec_redirection_instance_name: self})
    
    def update(self, type_, mecip_, proto_, port_, ueip_=None, dstip_=None):
        cursor = self.db_loc.cursor()
        if str(type_) == '1' :
            self.cpt=self.cpt+1
	    print(type_)
	    cursor.execute('''INSERT INTO mecrule VALUES (?,?,?,?,?,?,?);''',(self.cpt,str(type_),str(mecip_),str(ueip_),str(proto_),int(port_),str(dstip_)))
            self.cpt = self.cpt+1
            self.db_loc.commit()
	    self.logger.debug("DB updated %s", type_)
        elif str(type_) == 'all_tcp' or str(type_) == 'all_udp':
            self.cpt=self.cpt+1
	    cursor.execute('''INSERT INTO mecrule VALUES (?,?,?,?,?,?,?);''',(self.cpt,str(type_),str(mecip_),"NONE",str(proto_),int(port_),str(dstip_)))
	    self.db_loc.commit()
	    self.logger.debug("DB udpated %s", type_)
        else: 
            print("DB is not updated")

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        self.bdy = ev.msg.body
        print(self.bdy)
        
            
class MEControllerController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(MEControllerController, self).__init__(req, link, data, **config)
        self.mec_redirection_app = data[mec_redirection_instance_name]
 
    # adding a redirection rule to the database of the controller
    @route('mecredirection', url + '/add' , methods=['POST'])
    def update_db(self, req, **kwargs):
	
        mec_redirection = self.mec_redirection_app

        cursor = mec_redirection.db_loc.cursor()
        
        try:
            body = req.json if req.body else {}
        
        except ValueError:
            raise Response(status=400)

        print(body)
        try:   
                
	    t = body["Type"]
        
            ueip = None

            if t=='1':
                ueip = body ["UE-IP"]
        
            protocol = body["transport"]
            port = body["port"]
            mecip = body["MEC-IP"]
            dstip = body["dest"]
            cursor.execute('''SELECT * FROM mecrule WHERE proto=? AND dstip=? AND port=?;''',(str(protocol),str(dstip),port))
            rslt = cursor.fetchall()
            print(rslt)
            
            if rslt != [] :
                for i in rslt:
                    if i[1]=='all_tcp' or i[1]=='all_udp':
                        bdy = json.dumps({'result':'RULE_ALREADY_EXISTS'}, indent=4)
                        return Response(content_type='application/json', body=bdy) 
                    
                    if i[1]=='1':
                        if str(t)=='all_tcp' or str(t)=='all_udp':
                            cursor.execute('''DELETE FROM mecrule WHERE type=? AND dstip=? AND port=? AND proto=?;''',(str(i[1]),str(dstip),port,str(protocol)))
                            break
                        
                        elif str(t)=='1':
                            if str(ueip)==str(i[3]):
                                bdy = json.dumps({'result':'RULE_ALREADY_EXISTS'}, indent=4)
                                return Response(content_type='application/json', body=bdy)        

            if str(t)=='1':         
	        mec_redirection.update(t, mecip, protocol, port, ueip, dstip)
	        bdy = json.dumps({'result':'ok'}, indent=4)
                return Response(content_type='application/json', body=bdy)
        
            elif str(t)=='all_tcp' or str(t)=='all_udp':            
                mec_redirection.update(type_=t, mecip_=mecip, proto_=protocol, port_=port, dstip_=dstip)
                bdy = json.dumps({'result':'ok'}, indent=4)
                return Response(content_type='application/json', body=bdy)
            
        except Exception as e:
            print(e)  
            return Response(status=500) 

    # deleting a redirection rule from the database of the controller                          
    @route('mecredirection', url + '/delete' , methods=['POST'])
    def clean_db(self, req, **kwargs): 

        mec_redirection = self.mec_redirection_app

        cursor = mec_redirection.db_loc.cursor()
        
        try:
            body = req.json if req.body else {}
        
        except ValueError:
            raise Response(status=400)

        print(body)
        try:   
                
	    t = body["Type"]
        
            ueip = None

            if t=='1':
                ueip = body ["UE-IP"]
        
            protocol = body["transport"]
            port = body["port"]
            mecip = body["MEC-IP"]
            dstip = body["dest"]

            if str(t)=='1':
                cursor.execute('''DELETE FROM mecrule WHERE type=? AND mecip=? AND ueip=? AND proto=? AND dstip=? AND port=?;''',(str(t),str(mecip),str(ueip),str(protocol),str(dstip),port))
                mec_redirection.db_loc.commit()
                bdy = json.dumps({'result':'ok'}, indent=4)
                return Response(content_type='application/json', body=bdy)
            elif str(t)=='all_tcp' or str(t)=='all_udp':
                cursor.execute('''DELETE FROM mecrule WHERE type=? AND mecip=? AND proto=? AND dstip=? AND port=?;''',(str(t),str(mecip),str(protocol),str(dstip),port))
                mec_redirection.db_loc.commit()
                bdy = json.dumps({'result':'ok'}, indent=4)
                return Response(content_type='application/json', body=bdy)

        except Exception as e:
            print(e)  
            return Response(status=500)

    # displaying the redirection rules in the database of the controller
    @route('mecredirection', url + '/display' , methods=['GET'])
    def display_db(self, req, **kwargs):

        mec_redirection = self.mec_redirection_app

        cursor = mec_redirection.db_loc.cursor()

        cursor.execute('''SELECT * FROM mecrule;''')

        rslt = cursor.fetchall()

        rsltdct = {}

        dct = 1

        idd = "ID"
        typee = "Type"
        mecip = "MEC-IP"
        ueip = "UE-IP"
        proto = "transport"
        port = "port"
        dstip = "dest"

        for i in rslt:
            rsltdct.setdefault(dct,{})

            rsltdct[dct][idd] = i[0]
            rsltdct[dct][typee] = i[1]
            rsltdct[dct][mecip] = i[2]
            rsltdct[dct][ueip] = i[3]
            rsltdct[dct][proto] = i[4]
            rsltdct[dct][port] = i[5]
            rsltdct[dct][dstip] = i[6] 

            dct = dct + 1

        if rslt == []:
            bdy = json.dumps({'Database':'Empty'}, indent=4) 
            return Response(content_type='application/json', body=bdy)          

        elif rslt != []:
            bdy = json.dumps(rsltdct, indent=4)
            return Response(content_type='application/json', body=bdy) 
   
    # getting the statistics of the flow rules in the switch
    @route('mecredirection', url + '/stat' , methods=['GET'])
    def monitor(self, req, **kwargs):

        mec_redirection = self.mec_redirection_app

        for dp in mec_redirection.datapaths.values():
            mec_redirection._request_stats(dp)
        
        
        time.sleep(1)

        dct = 1
        statflow = {}


        for stat in [flow for flow in mec_redirection.bdy]:

            # check the flow rules with priority 0
            if stat.priority == 0:


                if stat.table_id == 1:
                
                
                    port_in = "IN-PORT"
                    packetcounter = "PACKETS"
                    bytecounter = "Bytes"
                    prior = "PRIORITY"
                    table = "TABLE"
                    port_out = "OUT-PORT"
                    destt = "Destination-IP"
        
                    statflow.setdefault(dct,{})
        
                    statflow[dct][prior] = stat.priority
                    statflow[dct][port_in] = stat.match['in_port']
                    statflow[dct][packetcounter] = stat.packet_count
                    statflow[dct][bytecounter] = stat.byte_count
                    statflow[dct][table] = stat.table_id
                    statflow[dct][port_out] = stat.instructions[0].actions[0].port
                    statflow[dct][destt] = "CONTROLLER"
            
                    dct = dct + 1

                elif stat.table_id == 0: 

                    packetcounter = "PACKETS"
                    bytecounter = "Bytes"
                    prior = "PRIORITY"
                    table = "TABLE"
        
                    statflow.setdefault(dct,{})
        
                    statflow[dct][prior] = stat.priority
                    statflow[dct][packetcounter] = stat.packet_count
                    statflow[dct][bytecounter] = stat.byte_count
                    statflow[dct][table] = stat.table_id
            
                    dct = dct + 1
            # check the flow rules with priority 40
            elif stat.priority == 40:                                                     
               
                if stat.table_id == 1:

                    try:
                        stat.match['ipv4_dst']
                    except KeyError:
                        ipv4_dst_exist = False
                    else:
                        ipv4_dst_exist = True 



                    try:
                        stat.match['ipv4_src']
                    except KeyError:
                        ipv4_src_exist = False
                    else:
                        ipv4_src_exist = True

                    try:
                        stat.match['tcp_dst']
                    except KeyError:
                        tcp_dst_exist = False
                        udp_dst_exist = True
                    else:
                        tcp_dst_exist = True
                        udp_dst_exist = False       
                                 
                    port_in = "IN-PORT"
                    packetcounter = "PACKETS"
                    bytecounter = "Bytes"
                    prior = "PRIORITY"
                    table = "TABLE"
                    port_out = "OUT-PORT"
                    sorcc = "Source-IP"
                    destt = "Destination-IP"
                    ethtype = "Ethernet-Type"
                    ipproto = "IP-Protocol"
        
                    statflow.setdefault(dct,{})

                    statflow[dct][prior] = stat.priority
                    statflow[dct][port_in] = stat.match['in_port']
                    statflow[dct][packetcounter] = stat.packet_count
            	    statflow[dct][bytecounter] = stat.byte_count
            	    statflow[dct][table] = stat.table_id
            	    statflow[dct][port_out] = stat.instructions[0].actions[2].port
                    statflow[dct][ethtype] = stat.match['eth_type']
                    statflow[dct][ipproto] = stat.match['ip_proto']

                    if ipv4_src_exist == True:
                        statflow[dct][sorcc] = stat.match['ipv4_src']

                    elif ipv4_src_exist == False:
                        statflow[dct][sorcc] = "Source Unknown"

                    if ipv4_dst_exist == True:
                        statflow[dct][destt] = stat.match['ipv4_dst']

                    elif ipv4_dst_exist == False:
                        statflow[dct][destt] = "Destination Unknown"

                    if tcp_dst_exist == True:
                        desttport = "TCP-Destination-Port"
                        statflow[dct][desttport] = stat.match['tcp_dst']

                    elif udp_dst_exist == True:
                        desttport = "UDP-Destination-Port"
                        statflow[dct][desttport] = stat.match['udp_dst']    

            	    dct = dct + 1

                elif stat.table_id == 0:

                    try:
                        stat.match['ipv4_dst']
                    except KeyError:
                        ipv4_dst_exist = False
                    else:
                        ipv4_dst_exist = True 



                    try:
                        stat.match['ipv4_src']
                    except KeyError:
                        ipv4_src_exist = False
                    else:
                        ipv4_src_exist = True

                    try:
                        stat.match['tcp_src']
                    except KeyError:
                        tcp_src_exist = False
                        udp_src_exist = True
                    else:
                        tcp_src_exist = True
                        udp_src_exist = False
                
                    port_in = "IN-PORT"
                    packetcounter = "PACKETS"
                    bytecounter = "Bytes"
                    prior = "PRIORITY"
                    table = "TABLE"
                    sorcc = "Source-IP"
                    destt = "Destination-IP"                
                    ethtype = "Ethernet-Type"
                    ipproto = "IP-Protocol"
              

                    statflow.setdefault(dct,{})

                    statflow[dct][prior] = stat.priority
                    statflow[dct][port_in] = stat.match['in_port']
                    statflow[dct][packetcounter] = stat.packet_count
            	    statflow[dct][bytecounter] = stat.byte_count
            	    statflow[dct][table] = stat.table_id
                    statflow[dct][ethtype] = stat.match['eth_type'] 
                    statflow[dct][ipproto] = stat.match['ip_proto']
      
                    if ipv4_src_exist == True:
                    	statflow[dct][sorcc] = stat.match['ipv4_src']

                    elif ipv4_src_exist == False:
                        statflow[dct][sorcc] = "Source Unknown"

                    if ipv4_dst_exist == True:
                    	statflow[dct][destt] = stat.match['ipv4_dst']

                    elif ipv4_dst_exist == False:
                    	statflow[dct][destt] = "Destination Unknown" 

                    if tcp_src_exist == True:
                        sorccport = "TCP-Source-Port"
                        statflow[dct][sorccport] = stat.match['tcp_src']

                    elif udp_src_exist == True:
                        sorccport = "UDP-Source-Port"
                        statflow[dct][sorccport] = stat.match['udp_src']               

                    dct = dct + 1  

            # check the flow rule(s) with priority 10  
            elif stat.priority == 10:                                                          
        
                if stat.table_id == 1:
                    port_in = "IN-PORT"
                    packetcounter = "PACKETS"
                    bytecounter = "Bytes"
                    prior = "PRIORITY"
                    table = "TABLE"
                    port_out = "OUT-PORT"
                    destt = "Destination-IP"
                    ethtype = "Ethernet-Type"
        
                    statflow.setdefault(dct,{})

                    statflow[dct][prior] = stat.priority
                    statflow[dct][port_in] = stat.match['in_port']
                    statflow[dct][packetcounter] = stat.packet_count
            	    statflow[dct][bytecounter] = stat.byte_count
            	    statflow[dct][table] = stat.table_id
            	    statflow[dct][port_out] = stat.instructions[0].actions[1].port
                    statflow[dct][destt] = stat.match['ipv4_dst']
                    statflow[dct][ethtype] = stat.match['eth_type']
 
                    dct = dct + 1
            
            # check the flow rule installed from SPGW-C                                          
            else:
                port_in = "IN-PORT"
                packetcounter = "PACKETS"
                bytecounter = "Bytes"
                prior = "PRIORITY"
                table = "TABLE"
                port_out = "OUT-PORT"
                destt = "Destination-IP"
                ethtype = "Ethernet-Type"
                tunid1 = "tun_ipv4_dst"
                tunid2 = "tunnel_id_nxm"    

                statflow.setdefault(dct,{})

                statflow[dct][prior] = stat.priority
                statflow[dct][port_in] = stat.match['in_port']
                statflow[dct][packetcounter] = stat.packet_count
            	statflow[dct][bytecounter] = stat.byte_count
            	statflow[dct][table] = stat.table_id
            	statflow[dct][port_out] = stat.instructions[0].actions[2].port
                statflow[dct][destt] = stat.match['ipv4_dst']
                statflow[dct][ethtype] = stat.match['eth_type']
                statflow[dct][tunid1] = stat.instructions[0].actions[0].value
                statflow[dct][tunid2] = stat.instructions[0].actions[1].value

            	dct = dct + 1                       
                                   
                                               
        bodyy = json.dumps(statflow, indent=4)
        return Response(content_type='application/json', body=bodyy)
     
