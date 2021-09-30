import json
import logging
import requests

from tornado.gen import multi

from handlers.base import MonitorHandler
from utils.network import async_post
from settings import PROFILING_URL, PS_HEADERS
from utils.utils import getDeviceID, raiseAlert, getSmarthomeID

logger = logging.getLogger("__main__").getChild(__name__)

malware_packages = [
    'com.guard.smart'
]

malware_signatures = [
    '0fb7e1d4a5d54d32827783326001480d'
]

package_details = {}

class ApplicationsMonitorHandler(MonitorHandler):
    async def post(self, device_id):
        payload = json.loads(self.request.body)
        #logger.info(payload)
        packages_temp = payload['data'][0].split('\n')
        packages = []
        for i in packages_temp:
            if i != "":
                # if i in malware_packages:
                #     logger.error("ALERT ALERT ALERT")
                details = i.split(":")[1]

                obj = {}
                package = details.split(' ')[0].split('=')[1]
                obj['path'] = details.split(' ')[0].split('=')[0]
                obj['signature'] = details.split(' ')[1]

                packages.append(package)

                package_details[package] = obj


        device_url = PROFILING_URL+"/device/"+getDeviceID(None, None)
        # logger.info("DEVICE URL: "+device_url)
        try:
            r = requests.get(PROFILING_URL+"/device/"+getDeviceID(None, None))
            if r.status_code == 200:
                device = json.loads(r.text)['data']

                if "packages" not in device:
                    patch_payload = {
                        "packages" : packages
                    } 

                    r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)
                else:
                    current_packages = device["packages"]
                    # logger.info(current_packages)
                    if set(current_packages) != set(packages):
                        # logger.info("Deviation detected")
                        patch_payload = {
                            "packages" : packages
                        } 
                        r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)

                        added_packages = set(packages) - set(current_packages)
                        removed_packages = set(current_packages) - set(packages)

                        logger.debug("PACKAGES INSTALLED")
                        logger.debug(list(added_packages))
                        logger.debug("PACKAGES UNINSTALLED")
                        logger.debug(list(removed_packages))


                        for pack in list(added_packages):
                            notification = False
                            if package_details[pack]["signature"] in malware_signatures:
                                notification = True
                                message = "Malware signature has been detected"
                            elif  pack in malware_packages:
                                notification = True
                                message = "Malware package has been detected"

                            if notification == True:
                                alert_data  = {
                                        "device_id" : getDeviceID(None, None),
                                        "smarthome_id" : getSmarthomeID(None, None),
                                        "message" : message,
                                        "notification_title" : message,
                                        "notification_description" : "Application "+ pack + " detected as malware.",
                                        "notification_type" : "Malware Detection",
                                        "metadata" : package_details[pack]
                                        }
                                raiseAlert(alert_data, criticality = 5, importance = 5, notification=True, compromised="maliciousCode")
                            else:
                                if len(list(added_packages)) > 0:
                                    alert_data  = {
                                            "device_id" : getDeviceID(None, None),
                                            "smarthome_id" : getSmarthomeID(None, None),
                                            "message" : "New application(s) have been installed",
                                            "metadata" : {
                                                    "packages" : list(added_packages)
                                                }
                                            }
                                    raiseAlert(alert_data, criticality = 1, importance = 1, notification=False)
                        
                        if len(list(removed_packages)) > 0:
                            alert_data  = {
                                    "device_id" : getDeviceID(None, None),
                                    "smarthome_id" : getSmarthomeID(None, None),
                                    "message" : "Application(s) have been removed",
                                    "metadata" : {
                                            "packages" : list(removed_packages)
                                        }
                                    }
                            raiseAlert(alert_data, criticality = 1, importance = 1, notification=False)


        except Exception as e:
            import sys
            _, _, exc_tb = sys.exc_info()
            logger.debug('{error} in line {line}'.format(error=str(e), line=exc_tb.tb_lineno))
            self.send_error(500, msg=str(e))
        
