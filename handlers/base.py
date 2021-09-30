import json
import logging

import tornado.web

from utils.network import async_post, check_patch_fields, check_post_fields

logger = logging.getLogger("__main__").getChild(__name__)

class MonitorHandler(tornado.web.RequestHandler):
    def initialize(self, fields, profiling_endpoint, alert_template):
        self.fields = fields
        self.profiling_endpoint = profiling_endpoint
        self.alert_template = alert_template

    def write_error(self, status_code, **kwargs):
        # exc_info (exc_type, exc_value, traceback) tuple
        exc_info = kwargs.get("exc_info", (None, "Unknown exception", None))
        logger.error(str(exc_info[1]))
        logger.debug(str(exc_info[2]))
        self.write({
                    "status": "error",
                    "message": str(exc_info[1]),
                    "data": []
                    })
        self.finish()

    def check_body(self):
        content_type = self.request.headers.get("Content-Type", "application/json")
        
        if content_type != "application/json":
            self.send_error(406, msg="Content type must be application/json")
        try:
            # logger.debug(self.request.body)
            bad_fields = check_post_fields(json.loads(self.request.body), self.fields)
            if bad_fields:
                raise ValueError("Missing or incorrect fields: " + str(bad_fields))
        except Exception as e:
            logger.error(str(e))
            self.send_error(400, msg=str(e))

    async def post(self, device_id):
        try:
            payload = json.loads(self.request.body)
            if "nameValuePairs" in payload:
                payload = payload["nameValuePairs"]

            response = await async_post(self.profiling_endpoint + device_id, payload)
            logger.debug(response.body.decode())
            if response.code == 201:
                self.set_status(201)
                self.finish({
                    "status": "success",
                    "message": "Data correctly sent to Profiling Service",
                    "data": []
                    })
            else:
                logger.error("Error connecting to Profiling Service")
                self.send_error(500, msg="Error connecting to Profiling Service. HTTP code: {} - {}".format(response.code, response.body.decode()))
        except Exception as e:
            logger.error("Error posting to Profiling Service")
            logger.error(str(e))
            self.send_error(500, msg=str(e))

