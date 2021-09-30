import json
import datetime
import time
import logging
import sys

import requests
from tornado.httpclient import AsyncHTTPClient
import stomp

from settings import HOST, PORT, ADIBUS_URL, RULES_ENDPOINT, ACTIVEMQ_HOST, ACTIVEMQ_PORT, PROFILING_URL
from utils.network import async_get, async_post
from utils.signatures import signMessage, checkMessage


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

post_headers = {"content-type":"application/json"}

DEVIATION_METRICS_TEMPLATE = {
    "device_id": "deviceId",
    "changeType": "metricDeviation",
    "deviationInfo": {
        "deviationType": "", # "CPUDeviation" | "networkDeviation" |"diskActivityDeviation" | ...,
        "nominalRangeLowEnd": 0,
        "nominalRangeHighEnd": 0,
        "detectedAvgMetricValue": 0,
        "detectedMaxMetricValue": 0,
        "startTimestamp": "",
        "endTimestamp": ""
    }
 }

NONCOMPLIENT_TRAFFIC_TEMPLATE = {
    "deviceId": "deviceId",
    "changeType": "nonCompliantTraffic",
    "trafficInfo": {
    "trafficPeer": "peerId or address",
    "trafficDirection": "fromDevice", #| "toDevice",
    "protocol": "protocolId",
    "protocolSpecificData": {}, #protocol specific data, e.g. port for TCP/IP
    "startTimestamp": "start time of non-compliant traffic",
    "endTimestamp": "end of reporting period",
    "numberOfPackets": 0,
    "dataVolume": 0
    }
}


def getDeviceID(rip, dip):
    return "609e2ca86ec17b06468abd1e"

def getSmarthomeID(rip, dip):
    return "60204d0e6ec17b0659145750"

def prepareAsyncMessage(payload):
    template = {
        "header":{
            "source": "ps1234.cybertrust.eu",
            "msg_topic": "",
            "msg_id": "",
            "cor_id": "",
            "timestamp": round(time.time()*1000),
            "sign_alg": "sha256WithRSAEncryption"
        },
        "payload": {},
    }
    template["payload"] = payload

    # payload_str = json.dumps(template, separators=(',', ':')).encode('utf-8')
    signature = signMessage(template)

    template["trailer"] = {
        "signature": signature # key is maybe "sig"
    }

    return template

def sendStompMessage(payload, topic):
    try:
        conn = stomp.Connection([(ACTIVEMQ_HOST, ACTIVEMQ_PORT)])
        conn.connect('', '', wait=True)
        conn.send(body=json.dumps(payload), destination='/topic/{topic}'.format(topic=topic))
        conn.disconnect()
        return True
    except Exception as e:
        return False

def raiseAlert(alert_data, criticality, importance, notification, compromised = None):
    alert_payload = {
            "alert_type" : "device",
            "device_id" : alert_data["device_id"],
            "smarthome_id" : alert_data["smarthome_id"],
            "device_type" : "smartphone",
            "reason" : {
                "rule_id" : "",
                "message" : alert_data["message"],
                "code" : 0
            },
            "criticality" : criticality,
            "importance" : importance,
            "metadata" : alert_data["metadata"]
        }

    alert_url = "http://172.16.4.43/alert/"

    r = requests.post(alert_url, data=json.dumps(alert_payload), headers=post_headers)
    print(r.text)

    alert_id = json.loads(r.text)['data']['_id']

    print(alert_id, compromised)

    if notification == True:
        notification_payload = {
                "to": "/topics/soho1",
                "title" : alert_data["message"],
                "data" : {
                    "tip" : alert_data["notification_title"],
                    "img": "https://cdn.pixabay.com/photo/2015/12/16/17/41/bell-1096280_960_720.png",
                    "description" : alert_data["notification_description"],
                    "type" : alert_data["notification_type"],
                    "threat_level" : criticality,
                    "originating_service" : "SDA"
                },
                "metadata": alert_data["metadata"]
            }

        fcm_headers = {
                'Content-Type': 'application/json',
                'Authorization': 'key=AAAAfN3rNqw:APA91bEg7Vgu_6o5U9hd9ViN9DiyEWcPpFBb9bc--6W9IDsM918oFcSCOy3jT9OAb5m7HySbBsl5lG6TgxjwSCsKEFRUS-L_brUr6_YlMwPA_MqaeuJ_Wai9LEI1Mvk_841rZshdwehn'
            }

        fcm_req = requests.post('https://fcm.googleapis.com/fcm/send', json=notification_payload, headers=fcm_headers)
        message_id = json.loads(fcm_req.text)['message_id']
        notification_payload['message_id'] = message_id

        notification_url = "http://172.16.4.43/notification/"

        r = requests.post(notification_url, data=json.dumps(notification_payload), headers=post_headers)
        print(r.text)

        if compromised != None:
            logger.debug("Trigger Compromised Message")
            sendCompromisedInfo(alert_data["device_id"], compromised, alert_data["notification_description"], alert_id)


async def retrieveRules(device_id):
    query = {
        "keys": ["device_id"],
        "values": ["602288816ec17b0657144394"]
    }

    try:
        r = await async_post(RULES_ENDPOINT + "find", query)
        rules = json.loads(r.body)['data']
    except Exception as e:
        print(e)
    return rules


def applyRules(rules, data):
    """Apply Cybertrust rules to a given dictionary of key, value pairs

    For every piece of data not rule-compliant, it returns an object with the following structure:
    {
        "key": rule_key, # Same as data_key
        "operator": rule_operator
        "value": rule_value
        "actual_value": data_value
    }

    Return: list of objects, or empty list (equivalent to False in if clauses)
    
    Implementation is a little dirty, basically we iterate over the given rules and then over
    the conditions in each rule.

    When logical operator is OR, as soon as a condition is matched we set a flag to True and append
    an object to the return list.
    When logical operator is AND, as soon as a condition is *not* matched we set a flag to True
    and break, and the object is appended to the return list only if we've execute the loop till the end.
    """

    deviations = []
    # logger.debug("Applying rules for specific device")
    # logger.debug("Rules: " + repr(rules), data)
    for monitoring_key, monitoring_value in data.items():
        for rule in rules:
            if not "condition" in rule:
                continue
            for condition in rule['condition']:
                if not "terms" in condition or not "logical_operator" in condition:
                    continue
                try:
                    logical_operator = condition['logical_operator']
                    if logical_operator == 'OR':
                        for term in condition['terms']:
                            flag = False
                            if not monitoring_key in term["key"]:
                                continue
                            
                            rule_value = term.get('value')
                            data_value = monitoring_value
                            # Curate percentages
                            if isinstance(rule_value, str):
                                rule_value = int(rule_value.strip('%'))
                            if isinstance(data_value, str):
                                data_value = int(monitoring_value.strip('%'))

                            # logger.debug("term: {}".format(term))
                            # logger.debug("data_value: {}".format(data_value))
                            # logger.debug("rule_value: {}".format(rule_value))
                            if term.get('operator') == 'greater_than':
                                if data_value > rule_value:
                                    flag = True
                            elif term.get('operator') == 'less_than':
                                if data_value < rule_value:
                                    flag = True
                            elif term.get('operator') == 'equal_to':
                                if data_value == rule_value:
                                    flag = True
                            
                            if flag:
                                deviations.append({
                                        "key": monitoring_key,
                                        "operator": term.get('operator'),
                                        "value": rule_value,
                                        "actual_value": data_value
                                    })

                    elif logical_operator == 'AND':
                        flag = False
                        temp_deviation = {}
                        for term in condition['terms']:
                            if not monitoring_key in term["key"]:
                                continue

                            rule_value = term.get('value')
                            data_value = monitoring_value

                            # Curate percentages
                            try:
                                if isinstance(rule_value, str):
                                    rule_value = int(rule_value.strip('%'))
                                if isinstance(data_value, str):
                                    data_value = int(monitoring_value.strip('%'))
                            except ValueError as ve:
                                pass
                            # logger.debug("term: {}".format(term))
                            # logger.debug("data_value: {}".format(data_value))
                            # logger.debug("rule_value: {}".format(rule_value))

                            if term.get('operator') == 'greater_than':
                                if data_value > rule_value:
                                    temp_deviation.update({
                                        "key": monitoring_key,
                                        "operator": term.get("operator"),
                                        "min_value": rule_value,
                                        "actual_value": data_value
                                    })
                                    flag = True
                                else:
                                    flag = False
                                    break
                            elif term.get('operator') == 'less_than':
                                if data_value < rule_value:
                                    temp_deviation.update({
                                        "key": monitoring_key,
                                        "operator": term.get("operator"),
                                        "max_value": rule_value,
                                        "actual_value": data_value
                                    })
                                    flag = True
                                else:
                                    flag = False
                                    break
                            elif term.get('operator') == 'equal_to':
                                if data_value == rule_value:
                                    temp_deviation.update({
                                        "key": monitoring_key,
                                        "operator": term.get("operator"),
                                        "value": rule_value,
                                        "actual_value": data_value
                                    })
                                    flag = True
                                else:
                                    flag = False
                                    break
                        if flag:
                            deviations += temp_deviations

                except Exception as e:
                    logger.error("Error when applying rule")
                    logger.error(str(e))
                    continue
    return deviations

async def sendDeviationInfo(deviation, device_id, deviation_type):
    try:    
        tmsPayload = DEVIATION_METRICS_TEMPLATE
        tmsPayload["deviationInfo"]["deviationType"] = deviation_type
        tmsPayload["deviationInfo"]["nominalRangeLowEnd"] = "0" #deviation.get("max_value")
        tmsPayload["deviationInfo"]["nominalRangeHighEnd"] = "80" #deviation.get("min_value")
        tmsPayload["deviationInfo"]["detectedAvgMetricValue"] = deviation.get("actual_value")
        tmsPayload["deviationInfo"]["detectedMaxMetricValue"] = str(deviation.get("actual_value"))
        tmsPayload["deviationInfo"]["startTimestamp"] = datetime.datetime.today().isoformat()
        tmsPayload["deviationInfo"]["endTimestamp"] = datetime.datetime.today().isoformat()
        tmsPayload["device_id"] = device_id

        async_r = await async_post(PROFILING_URL + "deviation/", data=tmsPayload)
        if async_r.code != 201:
            logger.error("Error when posting deviation to Profiling Service")
            logger.debug(async_r.body)
        else:
            logger.info("Deviation data succesfully sent to Profiling Service")
            # field in TMS is deviceId
            tmsPayload["deviceId"] = tmsPayload["device_id"] 
            del tmsPayload["device_id"]

            wan = await getSmarthomeIP(device_id)
            if not wan:
                logger.error("Couldn't send deviation to CT BUS, unknown SOHO")
                return
            soho_topic = topicFromWAN(wan)
            tmsPayloadS = prepareAsyncMessage(tmsPayload)
            if sendStompMessage(tmsPayloadS, "{}.Device.Alert".format(soho_topic)):
                logger.info("Deviation data succesfully sent to TMS")
            else:
                logger.error("Error sending message to CT BUS")
    except Exception as e:
        logger.error("Error when sending deviation info")
        logger.error(str(e))

def sendCompromisedInfo(device_id, compromise_type, message, alert_id):
    try:
        logger.debug("Prepare Compromised messages")
        tmsPayload = {
                    "deviceId" : device_id,
                    "changeType": "deviceCompromised",
                    "compromisedElements": [
                        {
                            "compromiseType": compromise_type,
                            "compromisedElementID" : "",
                            "additionalInfo" : message
                        }
                    ]
                }

        psPayload = {
                "device_id" : device_id,
                "type" : compromise_type,
                "detector" : "SDA",
                "alerts" : [alert_id],
                "additional_info" : message,
                "status" : ""
                }

        async_r = requests.post(PROFILING_URL + "compromised/", data=json.dumps(psPayload), headers=post_headers)
        if async_r.status_code != 201:
            logger.error("Error when posting compromise to Profiling Service")
            logger.debug(async_r.text)
        else:
            logger.info("Compromise data succesfully sent to Profiling Service")
            logger.debug(async_r.text)
            # field in TMS is deviceId

            #wan = getSmarthomeIP(device_id)
            #if not wan:
            #    logger.error("Couldn't send deviation to CT BUS, unknown SOHO")
            #    return
            soho_topic = "4036"
            tmsPayloadS = prepareAsyncMessage(tmsPayload)
            if sendStompMessage(tmsPayloadS, "{}.Device.Compromised".format(soho_topic)):
                logger.info("Compromised data succesfully sent to TMS")
            else:
                logger.error("Error sending message to CT BUS")
    except Exception as e:
        logger.error("Error when sending compromised info")
        logger.error(str(e))


async def getSmarthomeIP(device_id):
    async_r = await async_get(PROFILING_URL + "smarthome/device_id/" + str(device_id))
    if async_r.code != 200:
        logger.error("Error when getting smarthome IP for device " + device_id)
        logger.debug(async_r.body)
        return None
    soho = json.loads(async_r.body).get("data", {})
    return soho.get("WAN")

def topicFromWAN(wan):
    ip_parts = wan.split(".")
    # 172.20.20x.xxx or 172.16.x.xxx but it's the same
    return f"{ip_parts[-2][-1]}{ip_parts[-1].zfill(3)}"

def ISODateFromString(string):
    return datetime.datetime.strptime(string, "%Y-%m-%d").isodate()

def ISODateTimeFromString(string):
    dt = datetime.datetime.strptime(string, "%Y-%m-%dT%H:%M:%S")
    return dt.isoformat('T')

async def createSubscription(topic, username, endpoint):
    data = {
                "topic": topic,
                "username": username,
                "endpoint": endpoint
            }
    headers = {
        "OWNER": username,
        "Content-Type": "application/json"
    }

    try:
        r = await async_post(ADIBUS_URL + 'api/v1/routes/', data, headers)
        if r.status_code == 200:
            #logger.info('Subscribed to monitor topic')
            return topic
        else:
            return
    except Exception:
        #logger.warning("Couldn't subscribe to adiBus monitoring topics")
        return
