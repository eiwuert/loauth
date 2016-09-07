"""
oauth implementation testing skeleton
"""
from argparse import ArgumentParser
from logging import getLogger
from logging import DEBUG
from logging import StreamHandler
from BaseHTTPServer import HTTPServer
from sys import stdout
from sys import exit as sysexit
from getpass import getpass

from . import OAuth2HTTPRequestHandler
from . import adduser
from . import listusers
from . import listclients
from . import deluser
from . import delclient
from . import addclient
from . import moduser
from . import modclient
from . import create_database
from . import user_pass_authenticate


def setup_logging():
    """
    set up logging to standard out
    """
    log = getLogger('oauthlib')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)

    log = getLogger('loauth')
    log.addHandler(StreamHandler(stdout))
    log.setLevel(DEBUG)

    log = getLogger('database')
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
    # httpd.handle_request()


def parse_arguments():
    """
    parse command line arguments
    """
    parser = ArgumentParser(description="Libbit OAuth Server")
    parser.add_argument(
        '--add-user',
        dest='newuser',
        nargs=1,
        help="add a new user",
        metavar=("USERNAME"))
    parser.add_argument(
        '--mod-user',
        dest='moduser',
        nargs=1,
        help="change the password of a user",
        metavar=("USERNAME"))
    parser.add_argument(
        '--del-user',
        dest='deluser',
        nargs=1,
        help="remove a user",
        metavar=("USERNAME"))
    parser.add_argument(
        '--list-users',
        dest='listuser',
        action='store_true',
        help="list available users")
    parser.add_argument(
        '--authenticateuser',
        dest="authenticateuser",
        nargs=1,
        help="try authentication as USERNAME",
        metavar=("USERNAME"))

    parser.add_argument(
        '--add-client',
        dest='newclient',
        nargs=3,
        help="add a new client",
        metavar=(
            "CLIENT_ID",
            "CLIENT_SECRET",
            "USERNAME"))
    parser.add_argument(
        '--mod-client',
        dest='modclient',
        nargs=1,
        help="change the secret of a client",
        metavar=("CLIENT_ID"))
    parser.add_argument(
        '--del-client',
        dest='delclient',
        nargs=1,
        help="remove a client",
        metavar=("CLIENT_ID"))
    parser.add_argument(
        '--list-clients',
        dest='listclients',
        nargs='?',
        help="list available clients",
        metavar=("USERNAME"))
    parser.add_argument(
        '--authenticateclient',
        dest="authenticateclient",
        nargs=1,
        help="try authentication as CLIENT_ID",
        metavar=("CLIENT_ID"))

    parser.add_argument(
        '--init-db',
        dest='initdb',
        action='store_true',
        help="Initialise Database")
    parser.add_argument(
        '--password',
        dest='password',
        nargs=1,
        help="use PASSWORD for this user/client",
        metavar=("PASSWORD"))
    return parser.parse_args()

if __name__ == '__main__':
    setup_logging()

    logger = getLogger('loauth')
    start_program = True
    result = parse_arguments()

    if result.initdb:
        logger.info("cli init database")
        create_database()
        start_program = False

    if result.listuser:
        for user in listusers():
            getLogger(__name__).debug(user)
        start_program = False

    if result.listclients is not None:
        user = None
        if len(result.listclients) > 0:
            user = result.listclients[0]
            result = listclients(user)
        else:
            result = listclients()
        for user, clients in result.iteritems():
            getLogger(__name__).debug("Client list for user %s", user)
            for client in clients:
                getLogger(__name__).debug(" %s", client)
        start_program = False

    if 'newuser' in result and result.newuser is not None:
        logger.info("cli adding user " + result.newuser[0])
        # TODO Ask password if not given
        if result.password is not None:
            password = result.password[0]
        else:
            password = getpass(prompt="New password: ")
        adduser(result.newuser[0], password)
        start_program = False

    if 'modclient' in result and result.modclient is not None:
        logger.info('cli changing password for client ' + result.modclient[0])
        if result.password is not None:
            password = result.password[0]
        else:
            password = getpass(prompt="Password: ")
        modclient(result.modclient[0], password)
        start_program = False

    if 'moduser' in result and result.moduser is not None:
        logger.info('cli changing password for user ' + result.moduser[0])
        if result.password is not None:
            password = result.password[0]
        else:
            password = getpass(prompt="Password: ")
        moduser(result.moduser[0], password)
        start_program = False

    if 'newclient' in result and result.newclient is not None:
        logger.info("cli adding client" + result.newclient[0])
        addclient(
            result.newclient[0],
            result.newclient[1],
            result.newclient[2])
        start_program = False

    if 'delclient' in result and result.delclient is not None:
        logger.info("cli removing user " + result.delclient[0])
        delclient(result.delclient[0])
        start_program = False

    if 'deluser' in result and result.deluser is not None:
        logger.info("cli removing user " + result.deluser[0])
        deluser(result.deluser[0])
        start_program = False

    if 'authenticateuser' in result and result.authenticateuser is not None:
        username = result.authenticateuser[0]
        logger.info("CLI authentication of " + result.authenticateuser[0])
        if result.password is not None:
            password = result.password[0]
        else:
            password = getpass(prompt="Password: ")
        result = user_pass_authenticate(username, password, False)
        getLogger(__name__).debug(result)
        if result:
            getLogger(__name__).debug("Success")
            sysexit(0)
        else:
            getLogger(__name__).debug("Failure")
            sysexit(1)

    if 'authenticateclient' in result and result.authenticateclient is not None:
        logger.info("CLI authentication of " + result.authenticateclient[0])
        username = result.authenticateclient[0]
        if result.password is not None:
            password = result.password[0]
        else:
            password = getpass(prompt="Secret: ")
        result = user_pass_authenticate(username, password, True)
        getLogger(__name__).debug(result)
        if result:
            getLogger(__name__).debug("Success")
            sysexit(0)
        else:
            getLogger(__name__).debug("Failure")
            sysexit(1)

    if start_program:
        run()
