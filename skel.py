"""
oauth implementation testing skeleton
"""
from pprint import pprint
import inspect
from types import MethodType
from urllib import unquote_plus

from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from MySQLdb import connect
from MySQLdb import Error
from base64 import b64decode
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import WebApplicationServer
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError
from oauthlib.oauth2.rfc6749.errors import MissingClientIdError
from oauthlib.oauth2.rfc6749.errors import UnsupportedResponseTypeError
from oauthlib.oauth2.rfc6749.errors import UnauthorizedClientError
from traceback import format_stack


import logging
import sys
log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


class ClientStub:
    def __init__(self, client_id):
        self.client_id = client_id

def mysql_execute(command):
    """
    Function to execute a sql statement on the mysql database
    """
    try:
        connection = connect('localhost', 'user', 'pass', 'test')
        cursor = connection.cursor()
        cursor.execute(command)
        return cursor.fetchall()
    except Error as mysqlerror:
        print "MySQL Error: %d: %s" % (mysqlerror.args[0], mysqlerror.args[1])
    finally:
        if connection:
            connection.close()


class LocalboxRequestValidator(RequestValidator):
    """
    Checks correctness of the various aspects of the oauthlib server
    """
    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        validates the client_id. Since this is either 'ios' or 'android', and
        this source code document is publicly available, the amount of
        security gained from this is practially none.
        """
        print "validate client id"
        result = mysql_execute("select * from clients where id = " + client_id)
        return len(result) == 1

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """
        Redirect url for when none is given
        """
        print "get default redirect uri"
        return '/authenticated'

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """
        TODO: check validity if redirect uri
        """
        print "validate redirect uri"
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        TODO: save authcode
        """
        print "NEW: save authorization code"
        pprint(code)


    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """
        checks the validity of the response_type value.
        """
        print "validate response type"
        types = response_type.split(" ")
        return_value = True
        for rtype in types:
            if rtype not in ['code', 'token']:
                return_value = False
                print "falsified response type"
        return return_value

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """
        returns security scopes.
        """
        print "get default scopes"
        return 'all'

    def validate_scopes(self, client_id, scopes, client, request, *args,
                        **kwargs):
        """
        validates validity of the given scope.
        """
        print "validate scopes"
        return True

    def authenticate_client(self, request, *args, **kwargs):
        print "NEW: authenticate client WOOTISDOEWATIWANTZ"
        authorization_header_contents = request.headers['authorization']
        if http_authenticate(authorization_header_contents):
            if not request.client:
                request.client = ClientStub(u'10')
            return True
        else:
            return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        print "NEW: authenticate client id"
    def confirm_redirect_uri(self,  client_id, code, redirect_uri, client,
            request, *args, **kwargs):
        print "NEW: confirm redirect uri"
    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        print "NEW: get original scopes"
    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        print "NEW: invalidate authorization code"
    def save_bearer_token(self, token, request, *args, **kwargs):
        print "NEW: save bearer token"
    def validate_bearer_token(self, token, scopes, request):
        print "NEW: validate bearer token"
    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        print "NEW: validate code"
        #OBS! The request.user attribute should be set to the resource owner
        #associated with this authorization code. Similarly request.scopes and
        #request.state must also be set.
        request.scopes=""
	request.state=""
        return True
    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        print "NEW: validate grant type"
        return True
    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        print "NEW: validate refresh token"
    def validate_user(self, username, password, client, request, *args, **kwargs):
        print "NEW: validate user"

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
            *args, **kwargs):
        print "NEW: confirm redirect uri (altered to actually be callable)"
        return True




#authenticate_client authenticate_client_id confirm_redirect_uri get_original_scopes invalidate_authorization_code save_bearer_token validate_bearer_token validate_code validate_grant_type validate_refresh_token validate_user


def http_authenticate(authorization_header_contents):
    """
    Does (basic) HTTP authentication
    example line: Basic bmlkbzpwYXNzOm9yZA==
    NOTE: This implementation cannot handle usernames with colons.
    """
    if authorization_header_contents is None:
        return False
    try:
        authtype, authdata = authorization_header_contents.split(" ")
        assert authtype == "Basic"
    except(ValueError, AssertionError) as error:
        print "Cannot authenticate: " + error.message
        print authorization_header_contents
        print authtype
        return False
    data = b64decode(authdata)
    username, password = data.split(":", 1)
    # TODO: this is a bad implementation due sql injection
    result = mysql_execute("select * from users where name = '" + username +
                           "' and pass = '" + password + "';")
    return len(result) == 1

def add_authserver(self, authserver):
    self.authserver = authserver
    return


class OAuth2HTTPRequestHandler(BaseHTTPRequestHandler):
    """
    handles oauth requests
    """

    authserver = WebApplicationServer(LocalboxRequestValidator())

    def do_POST(self):  # pylint: disable=invalid-name
        uri = self.path
        http_method = self.command
        content_length = int(self.headers.getheader('Content-Length', 0))
        body = self.rfile.read(content_length)
        headers = self.headers
	scopes='none'
	credentials=None
        try:
            #headers, body, status = self.authserver.create_authorization_response(self.path, self.command, body, self.headers, scopes, credentials)
            #headers, body, status = self.authserver.create_authorization_response(self.path, self.command, body, self.headers, scopes, credentials)
            headers, body, status = self.authserver.create_token_response(self.path, self.command, body, self.headers, credentials)
            self.send_response(status)
            for key, value in headers.iteritems():
                self.send_header(key, value)
            self.end_headers()
        except OAuth2Error as error:
            if error.message:
                print "Message: " + error.message
            if error.description:
                print "Description: " + error.description
        self.wfile.write("<h1>Authenticated with POST MOTHAFUCKA!</h1>")
        
    def do_GET(self):  # pylint: disable=invalid-name
        """
        handle a HTTP GET request
        """
        authenticationheader = self.headers.getheader('Authorization')
        content_length = self.headers.getheader('Content-Length', 0)
        body = self.rfile.read(content_length)
        
        try:
            scopes, credentials = self.authserver.validate_authorization_request(
                self.path, self.command, body, self.headers.dict)
            # store credentials somewhere
            headers, body, status = self.authserver.create_authorization_response(self.path, self.command, body, self.headers, scopes, credentials)
            self.send_response(status)
            for key, value in headers.iteritems():
                self.send_header(key, value)
            self.end_headers()
        except OAuth2Error as error:
            print("OAuth2 Error: " + error.error)
            if error.message:
                print "Message: " + error.message
            if error.description:
                print "Description: " + error.description
        return

def run():
    """
    start the test server.
    """
    server_address = ('127.0.0.1', 8000)
    httpd = HTTPServer(server_address, OAuth2HTTPRequestHandler)
    #authserver = WebApplicationServer(LocalboxRequestValidator())
    #httpd.add_authserver = MethodType(add_authserver, httpd, HTTPServer)
    #httpd.add_authserver(authserver)
    print 'http server is running'
    httpd.handle_request()
    #httpd.serve_forever()

if __name__ == '__main__':
    run()
