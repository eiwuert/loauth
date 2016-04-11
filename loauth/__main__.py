"""
oauth implementation testing skeleton
"""
from argparse import ArgumentParser
from logging import getLogger
from logging import DEBUG
from logging import StreamHandler
from BaseHTTPServer import HTTPServer
from sys import stdout

from . import OAuth2HTTPRequestHandler
from . import adduser
from . import deluser
from . import addclient

def setup_logging():
    log = getLogger('oauthlib')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)

    log = getLogger('loauth')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)

def run():
    """
    start the test server.
    """
    getLogger("loauth").debug("start program")
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, OAuth2HTTPRequestHandler)
    httpd.serve_forever()
    #httpd.handle_request()

if __name__ == '__main__':
    setup_logging()
    logger = getLogger('loauth')
    start_program = True
    parser = ArgumentParser(description="Libbit OAuth Server")
    parser.add_argument('--add-user', dest='newuser', nargs=2, help="add a new user", metavar=("USERNAME","PASSWORD"))
    parser.add_argument('--add-client', dest='newclient', nargs=2, help="add a new client", metavar=("CLIENT_ID","CLIENT_SECRET"))
    parser.add_argument('--del-user', dest='deluser', nargs=1, help="remove a user", metavar=("USERNAME"))
    result = parser.parse_args()
    if result.newuser !=  None:
        logger.info("cli adding user " + result.newuser[0])
        adduser(result.newuser[0], result.newuser[1])
        start_program = False
    if result.newclient != None:
        logger.info("cli adding client" + result.newclient[0])
        addclient(result.newclient[0], result.newclient[1])
        start_program = False
    if result.deluser != None:
        logger.info("cli removing user " + result.deluser[0])
        deluser(result.deluser[0])
        start_program = False
    if start_program:
       run()
    print "end f the line"
