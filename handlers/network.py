import json
import logging
import requests

from tornado.gen import multi

from handlers.base import MonitorHandler
from utils.network import async_post
from settings import PROFILING_URL, PS_HEADERS

from utils.utils import getDeviceID, getSmarthomeID, raiseAlert

logger = logging.getLogger("__main__").getChild(__name__)
logger.addHandler(logging.NullHandler())

ignored_hosts = [
        '127.0.0.1',
        '172.16.4.43',
        '0.0.0.0'
        ]

suspicious_hosts = [
#        '62.138.0.117'
        ]


def parseNetstatLineLinux(line):
    fields = line.split()
    if len(fields) != 0 and fields[0][:3] == 'udp':
        field_num = 6
    elif len(fields) != 0 and fields[0][:3] == 'tcp':
        field_num = 7
    else:
        return None

    local_host, local_port = tuple(fields[3].rsplit(':', 1))
    remote_host, remote_port = tuple(fields[4].rsplit(':', 1))
    try:
        pid = fields[field_num-1].split("/")[0]
        pid = int(pid)
        program = fields[field_num-1].split("/")[-1]
    except Exception:
        pid = 0
        program = ""

    connection_data = {
        "protocol": str(fields[0].lower()),
        "recv_q": str(fields[1]),
        "send_q": str(fields[2]),
        "local_address": str(local_host),
        "local_port": str(local_port),
        "foreign_host": str(remote_host),
        "foreign_port": str(remote_port),
        "state": str(fields[field_num-2].upper()),
        "pid": pid,
        "program": str(program)
    }
    return connection_data

class NetstatMonitorHandler(MonitorHandler):
    async def post(self, device_id):
        payload = json.loads(self.request.body)
        # logger.info(payload)
        if isinstance(payload, dict):
            if "data" in payload:
                payload = payload.get("data")[0]
        if isinstance(payload, str) and payload != "":
            # It's not a valid JSON, but may be message from SDA app
            result = []
            try:
                for line in payload.split('\n')[1:-1]:
                    item = parseNetstatLineLinux(line)
                    if item:
                        result.append(item)

                payload = result
            except Exception as identifier:
                logger.error("Data is neither in JSON format nor in a valid netstsat/ifconfig format")
                self.send_error(400, msg="Data is neither in JSON format nor in a valid netstsat/ifconfig format")

            
        try:
            if isinstance(payload, list):
                open_ports = []
                open_connections = []
                open_connections_dict = {}

                for i in payload:
                    fh = i['foreign_host'].split(':')[-1]
                    if fh in ignored_hosts: # '172.16.4.43':
                        continue
                    obj = {
                            "local_port" : i['local_port'],
                            "foreign_port" : i['foreign_port'],
                            "foreign_host" : fh,
                            "pid" : i['pid']
                        }
                    open_connections.append(obj)
                    open_connections_dict[i['local_port']] = obj

                    open_ports.append(i['local_port'])

                #---------------->logger.info(open_ports)

                # logger.info(open_ports)

                device_url = PROFILING_URL+"/device/"+getDeviceID(None, None)
                # logger.info("DEVICE URL: "+device_url)
                try:
                    r = requests.get(PROFILING_URL+"/device/"+getDeviceID(None, None))
                    if r.status_code == 200:
                        device = json.loads(r.text)['data']

                        if "opened_ports" not in device:
                            patch_payload = {
                                "opened_ports" : open_connections
                            } 

                            r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)
                        else:
                            current_connections = device["opened_ports"]
                            current_connections_dict = {}
                            # logger.info(current_ports)
                            current_ports = []
                            for i in current_connections:
                                current_ports.append(i['local_port'])
                                current_connections_dict[i['local_port']] = i
                            if set(current_ports) != set(open_ports):
                                # logger.info("Deviation detected")
                                patch_payload = {
                                    "opened_ports" : open_connections
                                } 
                                r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)

                                added_ports = set(open_ports) - set(current_ports)
                                removed_ports = set(current_ports) - set(open_ports)

                                temp = []
                                for i in added_ports:
                                    temp.append(open_connections_dict[i])

                                #logger.debug("PORTS OPENED")
                                #logger.debug(temp)

                                for port in temp:
                                    notification = False
                                    if port["foreign_host"] in suspicious_hosts:
                                        notification = True
                                        message = "Connection with suspicious host"

                                    if notification == True:
                                        alert_data  = {
                                            "device_id" : getDeviceID(None, None),
                                            "smarthome_id" : getSmarthomeID(None, None),
                                            "message" : message,
                                            "notification_title" : message,
                                            "notification_description" : "Suspicious connection with address "+port['foreign_host']+" has been established.",
                                            "notification_type" : "Suspicious Connection",
                                            "metadata" : port
                                        }
                                        raiseAlert(alert_data, criticality = 5, importance = 5, notification=True)
                                        
                                if len(temp) > 0:
                                    alert_data  = {
                                        "device_id" : getDeviceID(None, None),
                                        "smarthome_id" : getSmarthomeID(None, None),
                                        "message" : "Network connections have been established",
                                        "metadata" : {
                                            "connections" : temp
                                            }
                                        }
                                    raiseAlert(alert_data, criticality = 1, importance = 1, notification=False)

                                temp = []

                                for i in removed_ports:
                                    temp.append(current_connections_dict[i])

                                #logger.debug("PORTS CLOSED")
                                #logger.debug(temp)
                                if len(temp) > 0:
                                    alert_data  = {
                                        "device_id" : getDeviceID(None, None),
                                        "smarthome_id" : getSmarthomeID(None, None),
                                        "message" : "Network connections have been closed",
                                        "metadata" : {
                                            "connections" : temp
                                        }
                                    }
                                    raiseAlert(alert_data, criticality = 1, importance = 1, notification=False)


                except Exception as e:
                    import sys
                    _, _, exc_tb = sys.exc_info()
                    logger.debug('{error} in line {line}'.format(error=str(e), line=exc_tb.tb_lineno))
                    self.send_error(500, msg=str(e))


                #logger.info("Posting {} elements of netstat data".format(len(payload)))
                #futures = [async_post(self.profiling_endpoint + device_id, data) for data in payload]
                #return_data = []
                #concurrency = 5
                # logger.error(len(futures))
                #while futures:
                #    if len(futures) > concurrency:
                #        r = await multi(futures[:concurrency])
                #        return_data += r
                #        futures = futures[concurrency:]
                #    else:
                #        r = await multi(futures[:len(futures)])
                #        return_data += r
                #        futures = []
                #if all([True for response in return_data if response.code == 201]):
                #    self.set_status(201)
                #    self.finish({
                #        "status": "success",
                #        "message": "Data correctly sent to Profiling Service",
                #        "data": []
                #        })
                #    return
                #else:
                #    self.send_error(500, msg="Error when connecting to Profiling Service")
            else:
                super().post(device_id)
        except Exception as e:
            import sys
            _, _, exc_tb = sys.exc_info()
            logger.debug('{error} in line {line}'.format(error=str(e), line=exc_tb.tb_lineno))
            self.send_error(500, msg=str(e))

class IfconfigMonitorHandler(MonitorHandler):
    async def post(self, device_id):
        payload = json.loads(self.request.body)
        
        try:
            # logger.info(payload)
            if isinstance(payload, dict):
                if "ifconfig" in payload:
                    payload = payload.get("ifconfig")

            if isinstance(payload, str) and payload != "":
                # It's not a valid JSON, but may be message from SDA app
                stats = []
                ip = []
                for line in payload.split('\n')[1:-1]:
                    if len(line.split(':')) == 2:
                        item = [line.split(':')[0].strip(), line.split(':')[1].split()]
                        if item[0] != "lo" and item[0] != "sit0":
                            obj = {
                                "rx_bytes" : item[1][0],
                                "rx_packages" : item[1][1],
                                "tx_bytes" : item[1][8],
                                "tx_packages" : item[1][9]
                            }
                            stats.append({"interface": item[0], "stats":obj})

                    if len(line.split(':')) > 2:
                        item = line.split()
                        if item[0] != "lo" and item[0] != "sit0":
                            for t_inter in stats:
                                if t_inter['interface'] == item[0]:
                                    t_inter['ip'] = item[2].split('/')[0]
                                    t_inter['mac'] : item[4]

                    # if item:
                    #     result.append(item)
                # payload = result
                # logger.info(stats)

                device_url = PROFILING_URL+"/device/"+getDeviceID(None, None)
                # logger.info("DEVICE URL: "+device_url)
                try:
                    r = requests.get(PROFILING_URL+"/device/"+getDeviceID(None, None))
                    if r.status_code == 200:
                        device = json.loads(r.text)['data']

                        # if "network_stats" not in device:
                        patch_payload = {
                            "network_stats" : stats
                        }

                        logger.info(patch_payload)

                        r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)
                        # else:
                        #     current_stats = device["network_stats"]
                        #     logger.info(current_stats)

                except Exception as e:
                    import sys
                    _, _, exc_tb = sys.exc_info()
                    logger.debug('{error} in line {line}'.format(error=str(e), line=exc_tb.tb_lineno))
                    self.send_error(500, msg=str(e))


                

            # if isinstance(payload, list):
                # logger.info("Posting {} elements of ifconfig data".format(len(payload)))
                # futures = [async_post(self.profiling_endpoint + device_id, data) for data in payload]
                # return_data = []
                # concurrency = 5
                # logger.error(len(futures))
                # while futures:
                #     if len(futures) > concurrency:
                #         r = await multi(futures[:concurrency])
                #         return_data += r
                #         futures = futures[concurrency:]
                #     else:
                #         r = await multi(futures[:len(futures)])
                #         return_data += r
                #         futures = []
                # logger.error(return_data)
                # if all(True for response in return_data if response.code == 201):
                #     self.set_status(201)
                #     self.finish({
                #         "status": "success",
                #         "message": "Data correctly sent to Profiling Service",
                #         "data": []
                #         })
                # else:
                #     self.send_error(500, msg="Error when connecting to Profiling Service")
            #     return
            # else:
            #     await super().post(device_id)
        except Exception as e:
            logger.debug(str(e))
            self.send_error(500, msg=str(e))
        return
