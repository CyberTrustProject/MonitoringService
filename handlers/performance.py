import json
import logging

from handlers.base import MonitorHandler
from utils.network import async_post
from utils.utils import prepareAsyncMessage, sendDeviationInfo, applyRules, retrieveRules, getDeviceID

PERFORMANCE_FIELDS = [
    ("cpu_overall", float),
    ("cpu_user", float),
    ("cpu_system", float),
    ("ram_usage", float),
    ("ram_total", float),
    ("ram_available", float),
    ("internal_storage_usage", float),
    ("external_storage_usage", float)
]

logger = logging.getLogger("__main__").getChild(__name__)

class PerformanceMonitorHandler(MonitorHandler):
    async def post(self, device_id):
        payload = json.loads(self.request.body)
        try:
            if (payload):
                for percent_field in PERFORMANCE_FIELDS:
                    percent_value = payload.get(percent_field, 0.0)
                    if ((percent_value < 0) or (percent_value > 100)):
                        self.send_error(400, msg="{} field is not a percentage.".format(percent_field))
        except Exception as e:
            print(e)


        try:
            device_id = getDeviceID(None,None)
            rules = await retrieveRules(device_id)
            deviations = applyRules(rules, payload)
            #device_id = "606ebed96ec17b05f8d1b7ea"
            for deviation in deviations:
                await sendDeviationInfo(deviation, device_id, "CPUDeviation")
            await super().post(device_id)
        except Exception as e:
            print(e)
            self.send_error(500, msg=str(e))
