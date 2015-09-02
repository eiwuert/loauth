"""
oauth implementation testing skeleton
"""
from json import dumps
from pprint import pprint
from logging import getLogger
from logging import DEBUG
from logging import StreamHandler

from ConfigParser import SafeConfigParser
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from MySQLdb import connect
from MySQLdb import Error
from base64 import b64decode
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import Server
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from oauthlib.common import generate_client_id


from datetime import datetime, timedelta
from sys import stdout

from __init__ import OAuth2HTTPRequestHandler


def run():
    """
    start the test server.
    """
    log = getLogger('oauthlib')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)
    log = getLogger('oauth')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)
    getLogger("oauth").debug("start program")
    server_address = ('127.0.0.1', 8000)
    httpd = HTTPServer(server_address, OAuth2HTTPRequestHandler)
    httpd.serve_forever()
    #httpd.handle_request()

if __name__ == '__main__':
    run()
