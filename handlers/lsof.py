import logging
import json
import csv
import requests

from tornado.gen import multi

from handlers.base import MonitorHandler
from utils.network import async_post
from settings import PROFILING_URL, PS_HEADERS

from utils.utils import getDeviceID, getSmarthomeID, raiseAlert

logger = logging.getLogger("__main__").getChild(__name__)

class LSOFMonitorHandler(MonitorHandler):
    async def post(self, device_id):
        # super().check_body()
        try:
            payload = json.loads(self.request.body)
            #logger.info(payload)
            if isinstance(payload, dict):
                payload = payload.get("data")[0]
            # TODO: This is working for Android, but not for Linux/Windows!!
            lines = payload.splitlines()[1:]
            ps_payload = []
            active_processes = []
            active_processes_dict = {}
            ap_payload = []
            for row in lines:
                lsof_row = row.split() # Splitting whitespaces, not tabs
                try:
                    lsof_detail = {}
                    # lsof_detail["command"] = lsof_row[0]
                    # lsof_detail["pid"] = int(lsof_row[1]) if lsof_row[1].isdigit() else None
                    # lsof_detail["user"] = lsof_row[2]
                    # lsof_detail["size"] = int(lsof_row[1]) if lsof_row[1].isdigit() else None
                    # lsof_detail["node"] = int(lsof_row[1]) if lsof_row[1].isdigit() else None
                    # lsof_detail["path"] = " ".join(lsof_row[8:])

                    lsof_detail["command"] = lsof_row[8]

                    if lsof_row[0] == "root" or lsof_row[0] == "system":
                        continue

                    if lsof_detail["command"] == "ps":
                        continue


                    lsof_detail["pid"] = int(lsof_row[1]) if lsof_row[1].isdigit() else None
                    # lsof_detail["user"] = lsof_row[2]
                    # lsof_detail["size"] = int(lsof_row[1]) if lsof_row[1].isdigit() else None
                    # lsof_detail["node"] = int(lsof_row[1]) if lsof_row[1].isdigit() else None
                    # lsof_detail["path"] = " ".join(lsof_row[8:])

                    if lsof_detail["pid"] in active_processes:
                        continue
                    
                    active_processes.append(lsof_detail["pid"])
                    obj = {
                        "command" : lsof_detail["command"],
                        "pid" : lsof_detail["pid"]
                    }

                    ap_payload.append(obj)
                    active_processes_dict[str(lsof_detail["pid"])] = obj
                    #ps_payload.append(lsof_detail)
                    

                    #if lsof_detail["path"].startswith("/data/app"):
                except IndexError:
                    continue
            # logger.info("Posting {} elements of lsof data".format(len(ps_payload)))
            # futures = [async_post(self.profiling_endpoint + device_id, data) for data in ps_payload]
            # return_data = []
            # concurrency = 10
            # while futures:
            #     if len(futures) > concurrency:
            #         r = await multi(futures[:concurrency])
            #         return_data += r
            #         futures = futures[concurrency:]
            #     else:
            #         r = await multi(futures[:len(futures)])
            #         return_data += r
            #         futures = []
            # logger.debug(return_data)
            # if all(True for response in return_data if response.code == 201):
            #     self.set_status(201)
            #     self.finish({
            #         "status": "success",
            #         "message": "Data correctly sent to Profiling Service",
            #         "data": []
            #         })
            # else:
            #     self.send_error(500, msg="Error when connecting to Profiling Service")
        # else:
        #     await super().post(device_id)
            
            
            # TO BE SENT
            #logger.debug(ap_payload)
            
            active_pids = active_processes
            active_processes = ap_payload
            #logger.debug(active_processes)

            device_url = PROFILING_URL+"/device/"+getDeviceID(None, None)
            # logger.info("DEVICE URL: "+device_url)
            try:
                r = requests.get(PROFILING_URL+"/device/"+getDeviceID(None, None))
                if r.status_code == 200:
                    device = json.loads(r.text)['data']

                    if "active_processes" not in device:
                        patch_payload = {
                            "active_processes" : active_processes
                        } 

                        r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)
                    else:
                        current_processes_temp = device["active_processes"]
                        current_processes = []
                        current_processes_dict = {}
                        for i in current_processes_temp:
                            current_processes.append(i["pid"])
                            current_processes_dict[str(i["pid"])] = i
                        
                        # logger.info(current_packages)
                        if set(current_processes) != set(active_pids):
                            # logger.info("Deviation detected")
                            patch_payload = {
                                "active_processes" : active_processes
                            } 
                            r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)

                            added_processes = set(active_pids) - set(current_processes)
                            removed_processes  = set(current_processes) - set(active_pids)

                            temp = []
                            
                            for i in added_processes:
                                temp.append(active_processes_dict[str(i)])

                            logger.debug("ActiveProcesses ADDED:")
                            logger.debug(temp)


                            if  len(temp) > 0:
                                alert_data  = {
                                    "device_id" : getDeviceID(None, None),
                                    "smarthome_id" : getSmarthomeID(None, None),
                                    "message" : "New process(es) have been activated",
                                    "metadata" : {
                                        "processes" : temp
                                    }
                                }
                                raiseAlert(alert_data, criticality = 1, importance = 1, notification=False)

                            temp = []

                            for i in removed_processes:
                                temp.append(current_processes_dict[str(i)])
                        
                            logger.debug("ActiveProcesses REMOVED:")
                            logger.debug(temp)
                        
                            if len(temp) > 0:
                                alert_data  = {
                                    "device_id" : getDeviceID(None, None),
                                    "smarthome_id" : getSmarthomeID(None, None),
                                    "message" : "Process(es) have been closed",
                                    "metadata" : {
                                        "processes" : temp
                                    }
                                }
                                raiseAlert(alert_data, criticality = 1, importance = 1, notification=False)



            except Exception as e:
                import sys
                _, _, exc_tb = sys.exc_info()
                logger.debug('{error} in line {line}'.format(error=str(e), line=exc_tb.tb_lineno))
                self.send_error(500, msg=str(e))

        except Exception as e:
            logger.debug("Exception: " + str(e))
            self.send_error(500, msg=str(e))
