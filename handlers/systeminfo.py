import logging
import json

from tornado.gen import multi

from handlers.base import MonitorHandler
from utils.network import async_post

logger = logging.getLogger("__main__").getChild(__name__)

class SystemInfoHandler(MonitorHandler):
    async def post(self, device_id):
        payload = json.loads(self.request.body)
        logger.info(payload)
        