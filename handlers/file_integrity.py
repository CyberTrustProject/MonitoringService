import requests
import hashlib
import os
import json
import logging
import math
from datetime import datetime, timezone

from tornado.gen import multi

from handlers.base import MonitorHandler
from utils.network import async_get, async_post, async_patch
from utils.utils import sendDeviationInfo, getDeviceID, getSmarthomeID, raiseAlert
from settings import CRITICAL_FILES_ENDPOINT, PROFILING_URL, PS_HEADERS

logger = logging.getLogger("__main__").getChild(__name__)
logger.addHandler(logging.NullHandler())

FILE_INTEGRITY_FIELDS = [
    ("filename", str),
    ("path", str),
    ("hash", str),
    ("algorithm", str),
    ("additional_info", str),
]

class FIMMonitorHandler(MonitorHandler):
	async def post(self, device_id):
                payload = json.loads(self.request.body)
		# payload = json.loads(self.request.body)
                # logger.info(payload)

                files_raw = payload['data']['nameValuePairs']

                files = []

                files_kv = {}

                device_details = {}
                r = requests.get(PROFILING_URL+"/device/"+getDeviceID(None, None))
                
                if r.status_code == 200:
                    device = json.loads(r.text)['data']
                else:
                    return;

                for key, value in files_raw.items():
                    if key == 'metadata':
                        details = value.split('\n')
                        for detail in details:
                            detail = detail.replace('[','')
                            detail = detail.replace(']','')
                            temp = detail.split(':')
                       
                            if len(temp) != 2:
                                continue

                            if temp[0].startswith("ro"):
                                device_details[temp[0]] = temp[1].strip()
                
                        if "device_properties" not in device:
                            patch_payload = {
                                "device_properties" : device_details
                            }
                            r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)
                        else:
                            current_details = device['device_properties']
                            matched = []
                            for key,value in device_details.items():
                                if key in current_details:
                                    if value != current_details[key]:
                                        obj = {
                                            "property" : key,
                                            "old_value" : value,
                                            "new_vlaue" : current_details[key]
                                        }
                                        matched.append(obj)

                            if len(matched) > 0:
                                alert_data  = {
                                    "device_id" : getDeviceID(None, None),
                                    "smarthome_id" : getSmarthomeID(None, None),
                                    "message" : "Device properties have been changed",
                                    "notification_title" : "Device Properties",
                                    "notification_description" : "Device properties have been changed.",
                                    "notification_type" : "Device Properties",
                                    "metadata" : {
                                        "properties" : matched
                                            }
                                    }
                                raiseAlert(alert_data, criticality = 4, importance = 4, notification=True)
                                patch_payload = {
                                    "device_properties" : device_details
                                }
                                r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)


                        continue
                    obj = {
                            "file" : key,
                            "signature" : value.split(' ')[0]
                            }
                    files.append(obj)
                    files_kv[key] = value.split(' ')[0]

                # print(files_kv)
                device_url = PROFILING_URL+"/device/"+getDeviceID(None, None)
                # logger.info("DEVICE URL: "+device_url)
                try:
                    if True:
                        device = json.loads(r.text)['data']

                        update_device = False
                        if "critical_files" not in device:
                            patch_payload = {
                                "critical_files" : files
                            }
                            r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)
                        else:
                            current_critical_files = device['critical_files']

                            if len(current_critical_files) == 0:
                                patch_payload = {
                                    "critical_files" : files
                                }
                                r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)
                            else:
                                update_device = False
                                #print(current_critical_files)
                                #print(files)
                                if len(current_critical_files) != len(files):
                                    update_device = True

                                for f in current_critical_files:
                                    if f['file'] not in files_kv:
                                        print(f['file'])
                                        update_device = True
                                        continue

                                    if f['signature'] != files_kv[f['file']]:
                                        alert_data  = {
                                            "device_id" : getDeviceID(None, None),
                                            "smarthome_id" : getSmarthomeID(None, None),
                                            "message" : "Critical file integrity issue",
                                            "notification_title" : "Critical File Integrity",
                                            "notification_description" : "Critical file "+ f['file'] + " signature mismathed.",
                                            "notification_type" : "Critical File",
                                            "metadata" : {
                                                "file" : f['file'],
                                                "old_sign" : f['signature'],
                                                "new_sign" : files_kv[f['file']]
                                                }
                                        }
                                        raiseAlert(alert_data, criticality = 5, importance = 5, notification=True, compromised="criticalFileAltered")
                                        update_device = True

                            if update_device == True:
                                patch_payload = {
                                    "critical_files" : files
                                    }
                                r_patch = requests.patch(PROFILING_URL+"device/"+getDeviceID(None, None), data=json.dumps(patch_payload), headers=PS_HEADERS)


                except Exception as e:
                    logger.error(e)






#		try:
#			previous_file_hashes = await async_get(CRITICAL_FILES_ENDPOINT + device_id)
#			if previous_file_hashes.code == 200:
#				previous_files = json.loads(previous_file_hashes.body).get("data", [])
#				if not previous_files:
#					# TODO: Not sure if files should be posted every time, guess not
#					if isinstance(payload, list):
#						logger.info("Posting {} elements of files data".format(len(payload)))
#						futures = [async_post(self.profiling_endpoint + device_id, data) for data in payload]
#						return_data = []
#						concurrency = 4
#						while futures:
#							if len(futures) > concurrency:
#								r = await multi(futures[:concurrency])
#								return_data += r
#								futures = futures[concurrency:]
#							else:
#								r = await multi(futures[:len(futures)])
#								return_data += r
#								futures = []
#						logger.debug(return_data)
#						if all(True for response in return_data if response.code == 201):
#							self.set_status(201)
#							self.finish({
#								"status": "success",
#								"message": "Data correctly sent to Profiling Service",
#								"data": []
#								})
#						else:
#							self.send_error(500, msg="Error when connecting to Profiling Service")
#					else:
#						await super().post(device_id)
#				else:
#					previous_filenames = [ f.get("filename") for f in previous_files]
#					previous_hashes = [ f.get("hash") for f in previous_files]
#					bad_files = []
#					for current_file in payload:
#						if "nameValuePairs" in current_file:
#							current_file = current_file["nameValuePairs"]
#						logger.debug(current_file)
#						if current_file.get("filename") in previous_filenames:
#							file_index = previous_filenames.index(current_file.get("filename"))
#							if current_file.get("hash") != previous_hashes[file_index]:
#								bad_files.append(current_file.get("filename"))
#							else:
#								continue
#					if bad_files:
#						for f in bad_files:
#							logger.info("Corrupt or modified file: {}".format(f))
#							# TODO: Deviation values must be int, not suitable for this alert
#							# Dumb deviation
#							deviation = {
#								"key": "critical_file",
#								"operator": "equal_to",
#								"value": 0,
#								"actual_value": 0
#							}
#							await sendDeviationInfo(deviation, device_id, "diskActivityDeviation")
#					self.set_status(200)
#					self.finish({
#							"status": "success",
#							"message": "Data correctly sent to Profiling Service",
#							"data": []
#							})
#			else:
#				self.send_error(500, msg="Error when retrieving monitored files from Profiling Service. HTTP code: {}".format(previous_file_hashes.code))
#		except Exception as e:
#			self.send_error(500, msg=str(e))

