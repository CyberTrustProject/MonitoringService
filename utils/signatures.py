import os
import json
import base64
import logging

from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD2, MD5, SHA1, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA

from settings import BASE_DIR

logger = logging.getLogger("__main__").getChild(__name__)

PRIVATE_KEY_PATH =  os.path.join("/var/www/CTAdaptor/main/src/certs", "private") 
PUBLIC_KEY_PATH = os.path.join("/var/www/CTAdaptor/main/src/certs") 

ALLOWED_SOURCES = ["tms1234.cybertrust.eu", "ps1234.cybertrust.eu"]
# Should be a list of sources with a corresponding public key stored somewhere



def signMessage(json_message):
    with open(os.path.join(PRIVATE_KEY_PATH, "key.pem"), 'rb') as pk:
        key = RSA.import_key(pk.read())
    
    h = SHA256.new(json.dumps(json_message, separators=(',',':')).encode('utf-8'))
    signature = pkcs1_15.new(key).sign(h)
    
    return base64.b64encode(signature).decode('utf-8')

def checkMessage(json_message):
    try:
        signature = json_message.get("trailer", {}).get("signature", "")
        if not signature:
            raise ValueError("Message doesn't contain a signature")
        del json_message["trailer"]
        logger.debug(json_message)

        source = json_message.get("header", {}).get("source", "")
        algorithm = json_message.get("header", {}).get("sign_alg", "")
        if source in ALLOWED_SOURCES:
            with open(os.path.join(PUBLIC_KEY_PATH, "{}.cert.pem".format(source)), 'rb') as pk:
                key = RSA.import_key(pk.read())
            h = getMessageHash(json.dumps(json_message, separators=(',',':')).encode('utf-8'), algorithm)
            pkcs1_15.new(key).verify(h, base64.b64decode(signature))
            return True
        else:
            raise ValueError("source '{}' not allowed".format(source))
    except ValueError as ve:
        logger.error(ve)
        return False


def getMessageHash(b_message, algorithm):
    """Calculate hash of binary string for a given signing algorithm
    
    Possible algorithms are the ones using RSA from the Java Signature package:
    https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Signature
    """
    if algorithm == 'MD2withRSA':
        h = MD2.new(b_message)
    elif algorithm == 'MD5withRSA':
        h = MD5.new(b_message)
    elif algorithm == 'SHA1withRSA':
        h = SHA1.new(b_message)
    elif algorithm == 'SHA384withRSA':
        h = SHA384.new(b_message)
    elif algorithm == 'SHA512withRSA':
        h = SHA512.new(b_message)
    else: # This is the default: SHA256withRSA
        h = SHA256.new(b_message)
    return h
