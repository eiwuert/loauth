"""
oauth implementation testing skeleton
"""
from argparse import ArgumentParser
from json import dumps
from pprint import pprint
from logging import getLogger
from logging import DEBUG
from logging import StreamHandler
from sys import argv
from argparse import ArgumentParser
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
from __init__ import adduser

def run():
    """
    start the test server.
    """
    log = getLogger('oauthlib')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)

    log = getLogger('loauth')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)

    getLogger("loauth").debug("start program")
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, OAuth2HTTPRequestHandler)
    httpd.serve_forever()
    #httpd.handle_request()

if __name__ == '__main__':
    parser = ArgumentParser(description="Libbit OAuth Server")
    parser.add_argument('--add-user', dest='newuser', nargs=2, help="add a new user", metavar=("USERNAME","PASSWORD"))
    result = parser.parse_args()
    if result.newuser !=  None:
        from pprint import pprint
        pprint(result)
        adduser(result.newuser[0], result.newuser[1])
    run()
