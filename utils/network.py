"""Network related utils.

Functions that deal with async requests, responses, and
payload management. Each one has their own docstring.
"""
from enum import Enum
import json

from tornado.log import gen_log
from tornado.simple_httpclient import SimpleAsyncHTTPClient
from tornado.httpclient import AsyncHTTPClient

from settings import HOST, PORT, ADIBUS_URL, RULES_ENDPOINT

def check_post_fields(payload, key_type):
    """Check POST data to prevent further processing if wrong.

    Args:
        payload: POST payload to check.
        key_type: A list of tuples representing the key name and type of fields

    Returns:
        An array with missing or wrong fields or an empty array,
        which equals to False in 'if' clauses
    """

    missing_or_wrong = []
    for kw, typeof in key_type:
        if kw not in payload:
            missing_or_wrong.append(kw)
        else:
            if isinstance(typeof, dict):
                nested_missing = check_post_fields(payload[kw], typeof.get("fields"))
                if (nested_missing):
                    for field in nested_missing:
                        missing_or_wrong.append('{}.{}'.format(kw, field))
                continue
            # Not the most beautiful code, sorry
            elif isinstance(typeof, list):
                if not isinstance(payload[kw], list):
                    missing_or_wrong.append(kw)
                    continue
                i = -1
                for element in payload[kw]:
                    i += 1
                    temp_key_name = "<element{}>".format(i)
                    nested_missing = check_post_fields({temp_key_name: element}, [(temp_key_name, typeof[0])])
                    if (nested_missing):
                        missing_or_wrong.append('{}.{}'.format(kw, nested_missing[0]))
            elif issubclass(typeof, Enum):
                try:
                    typeof(payload[kw])
                except Exception as e:
                    missing_or_wrong.append(kw)
            elif (not isinstance(payload[kw], typeof)):
                missing_or_wrong.append(kw)
    return missing_or_wrong

def check_patch_fields(payload, key_type):
    """Check PATCH data to prevent further processing if wrong.

    Args:
        payload: PATCH payload to check.
        key_type: A list of tuples representing the key name and type of fields

    Returns:
        An array with wrong fields or an empty array, which equals to False in 'if' clauses
    """

    wrong = []
    for kw, typeof in key_type:
        if kw in payload:
            if isinstance(typeof, dict):
                nested_missing = check_post_fields(payload[kw], typeof.get("fields"))
                if (nested_missing):
                    for field in nested_missing:
                        wrong.append('{}.{}'.format(kw, field))
                continue
            # Not the most beautiful code, sorry
            elif isinstance(typeof, list):
                if not isinstance(payload[kw], list):
                    wrong.append(kw)
                    continue
                try:
                    i = -1
                    for element in payload[kw]:
                        i += 1
                        temp_key_name = "<element{}>".format(i)
                        nested_missing = check_post_fields({temp_key_name: element}, [(temp_key_name, typeof[0])])
                        if (nested_missing):
                            wrong.append('{}.{}'.format(kw, nested_missing[0]))
                except TypeError or IndexError as e:
                    wrong.append(kw)
                continue
            elif issubclass(typeof, Enum):
                try:
                    typeof(payload[kw])
                except Exception as e:
                    wrong.append(kw)
            elif (not isinstance(payload[kw], typeof)):
                wrong.append(kw)
    return wrong

class NoQueueTimeoutHTTPClient(SimpleAsyncHTTPClient):
    def fetch_impl(self, request, callback):
        key = object()

        self.queue.append((key, request, callback))
        self.waiting[key] = (request, callback, None)

        self._process_queue()

        if self.queue:
            gen_log.debug("max_clients limit reached, request queued. %d active, %d queued requests." % (len(self.active), len(self.queue)))

async def async_post(endpoint, data, headers={"Content-Type": "application/json"}):
    """Make an async POST request using Tornado AsyncHTTPClient().

    Args:
        endpoint: string representing the URL
        data: Python dict, serializable by json library, with data to POST
        headers: Python dict with all the headers to send in the request

    Returns:
        An array with wrong fields or an empty array, which equals to False in 'if' clauses
    """
    client = AsyncHTTPClient()
    client.configure(NoQueueTimeoutHTTPClient, max_clients=4000)
    response = await client.fetch(endpoint, method='POST', headers=headers, body=json.dumps(data), raise_error=False)
    return response

async def async_patch(endpoint, data, headers={"Content-Type": "application/json"}):
    """Make an async POST request using Tornado AsyncHTTPClient().

    Args:
        endpoint: string representing the URL
        data: Python dict, serializable by json library, with data to POST
        headers: Python dict with all the headers to send in the request

    Returns:
        An array with wrong fields or an empty array, which equals to False in 'if' clauses
    """
    client = AsyncHTTPClient()
    client.configure(NoQueueTimeoutHTTPClient, max_clients=4000)
    response = await client.fetch(endpoint, method='PATCH', headers=headers, body=json.dumps(data), raise_error=False)
    return response

async def async_get(endpoint, headers={"Content-Type": "application/json"}):
    """Make an async GET request using Tornado AsyncHTTPClient().

    Args:
        endpoint: string representing the URL
        headers: Python dict with all the headers to send in the request

    Returns:
        tornado.httpclient.HTTPResponse
    """
    client = AsyncHTTPClient()
    response = await client.fetch(endpoint, method='GET', headers=headers, raise_error=False)
    return response
