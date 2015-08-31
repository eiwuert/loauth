"""
oauth implementation testing skeleton
"""
from pprint import pprint
from logging import StreamHandler
from logging import DEBUG

from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from MySQLdb import connect
from MySQLdb import Error
from base64 import b64decode
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import Server
from oauthlib.oauth2.rfc6749.errors import OAuth2Error

from datetime import datetime
from datetime import timedelta

import logging
import sys

log = logging.getLogger('oauthlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)
log = logging.getLogger('oauth')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

class ClientStub:
    def __init__(self, client_id):
        self.client_id = client_id
    def __str__(self):
        return "Client: "+self.client_id

def mysql_execute(command, params = None):
    """
    Function to execute a sql statement on the mysql database
    """
    logging.getLogger("oauth").debug("mysql_execute(" + command + ", " + str(params) + ")")
    try:
        connection = connect('localhost', 'user', 'pass', 'test')
        cursor = connection.cursor()
        cursor.execute(command, params)
        connection.commit()
        return cursor.fetchall()
    except Error as mysqlerror:
        print "MySQL Error: %d: %s" % (mysqlerror.args[0], mysqlerror.args[1])
    finally:
        try:
            if connection:
                connection.close()
        except UnboundLocalError:
            pass

def clear_bearer_tokens(client_id):
    """
    remove excess tokens
    """
    logging.getLogger("oauth").debug("clear_bearer_tokens(" + client_id+")")
    sql = "delete from bearer_tokens where client_id = %s;"
    mysql_execute(sql, (client_id, ))

class LocalBoxRequestValidator(RequestValidator):
    """
    Checks correctness of the various aspects of the oauthlib server
    """
    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        validates the client_id. Since this is either 'ios' or 'android', and
        this source code document is publicly available, the amount of
        security gained from this is practially none.
        """
        logging.getLogger("oauth").debug("validate_client_id(" + client_id + ")")
        result = mysql_execute("select * from clients where id = " + client_id)
        if result == None:
            return False
        return len(result) == 1

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """
        Redirect url for when none is given
        """
        logging.getLogger("oauth").debug("get_default_redirect_uri(" + client_id + ")")
        return 'http://localhost:8000/authenticated'

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """
        TODO: check validity if redirect uri
        """
        logging.getLogger("oauth").debug("validate_redirect_uri(" + client_id + ", " + redirect_uri + ")")
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        TODO: save authcode
        """
        logging.getLogger("oauth").debug("save_authorization_code()")
	sql = "insert into authentication_code (client_id, authcode) values (%s, %s);"
        params = ( client_id, code['code'] )
        mysql_execute(sql, params)

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """
        checks the validity of the response_type value.
        """
        logging.getLogger("oauth").debug("validate_response_type()")
        #TODO: filter certain response types because we cannot build certain things
        return True
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
        logging.getLogger("oauth").debug("get_default_scopes(" + client_id + ")")
        return 'all'

    def validate_scopes(self, client_id, scopes, client, request, *args,
                        **kwargs):
        """
        validates validity of the given scope.
        """
        logging.getLogger("oauth").debug("validate_scopes()")
        return True

    def validate_user(self, username, password, client, request, *args, **kwargs):
        logging.getLogger("oauth").debug("validate_user(" + username + ", " + password + ", " + str(client) + ")")
        return user_pass_authenticate(username, password)

    def authenticate_client(self, request, *args, **kwargs):
        logging.getLogger("oauth").debug("authenticate_client()")
        authorization_header_contents = request.headers.get('authorization', '')
        print authorization_header_contents
        if authorization_header_contents is not '':
            # basic http authentication unpacking
            client_id = b64decode(authorization_header_contents.split(" ")[1]).split(":")[0]

            if (authorization_header_contents[:5] == 'Basic'):
                result = basic_http_authenticate(authorization_header_contents, True)
                request.client = ClientStub(client_id)
                #validation related
                request.client_id = client_id
                return result
        else:
            username = request.headers.get('client_id', '')
            password = request.headers.get('client_secret', '')
            result = user_pass_authenticate(username, password, True)
            if result:
                request.client_id = username
                request.client = ClientStub(username)
            return result

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        logging.getLogger("oauth").debug("authenticate_client_id()")
        raise NotImplementedError('needs checking')

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        logging.getLogger("oauth").debug("get_original_scopes()")
        raise NotImplementedError('needs checking')
        return 'all'

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        logging.getLogger("oauth").debug("invalidate_authorization_code()")
        sql = "delete from authentication_code where client_id = %s and authcode = %s;"
        mysql_execute(sql, (client_id, code))
        return

    def save_bearer_token(self, token, request, *args, **kwargs):
        logging.getLogger("oauth").debug("save_bearer_token()")
        pprint(token)
        clear_bearer_tokens(request.client.client_id)

        sql = "insert into bearer_tokens (access_token, refresh_token, expires, scopes, client_id) values (%s, %s, %s, %s, %s)"
        enddate =  datetime.now() + timedelta(0,token['expires_in'],0,0,0,0)
        params = (token.get('access_token'), token.get('refresh_token'), enddate, token.get('scope'), request.client.client_id)
        mysql_execute(sql, params)

    def validate_bearer_token(self, token, scopes, request):
        logging.getLogger("oauth").debug("validate_bearer_token()")
        sql = "select * from bearer_tokens where access_token = %s and client_id = %s and expires > NOW()";
        params = refresh_token, client.client_id
        result = mysql_execute(sql, params)
        if result == None:
            return False
        return len(result) == 1

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        logging.getLogger("oauth").debug("validate_code()")
        #OBS! The request.user attribute should be set to the resource owner
        #associated with this authorization code. Similarly request.scopes and
        #request.state must also be set.
        #request.scopes="code where client_id = %s and authcode = %s and expires > NOW();"
        result = mysql_execute(sql, (client_id, code))
        if result == None:
            return False
        return len(result)==1

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        logging.getLogger("oauth").debug("validate_grant_type()")
        return True

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        logging.getLogger("oauth").debug("validate_refresh_token(" + refresh_token + ", " + client + ")")
        sql = "select * from bearer_tokens where refresh_token = %s and client_id = %s and expires > NOW()";
        params = refresh_token, client.client_id
        result = mysql_execute(sql, params)
        if result == None:
            return False
        return len(result) == 1


    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
            *args, **kwargs):
        logging.getLogger("oauth").debug("confirm_redirect_uri()")
        raise NotImplementedError('needs checking')
        return True

def user_pass_authenticate(username, password, authenticate_client = False):
    logging.getLogger("oauth").debug("user_pass_authenticate(" + username + ", " + password + ", " + str(authenticate_client) + ")")
    if authenticate_client:
        result = mysql_execute("select 1 from clients where id= %s and secret = %s;",
                           (username, password))
    else:
        result = mysql_execute("select 1 from users where user = %s and pass = %s;",
                           (username, password))
    if result == None:
        return False
    return len(result) == 1

def basic_http_authenticate(authorization_header_contents, authenticate_client=False):
    """
    Does (basic) HTTP authentication
    example line: Basic bmlkbzpwYXNzOm9yZA==
    NOTE: This implementation cannot handle usernames with colons.
    """
    logging.getLogger("oauth").debug("basic_http_authenticate(" + authorization_header_contents+ ", " + str(authenticate_client) + ")")
    if authorization_header_contents is None:
        return False
    try:
        authtype, authdata = authorization_header_contents.split(" ")
        assert authtype == "Basic"
    except(ValueError, AssertionError) as error:
        print "Cannot authenticate: " + error.message
        return False
    data = b64decode(authdata)
    username, password = data.split(":", 1)
    # TODO: this is a bad implementation due sql injection
    return user_pass_authenticate(username, password, authenticate_client=authenticate_client)

class OAuth2HTTPRequestHandler(BaseHTTPRequestHandler):
    """
    handles oauth requests
    """

    authserver = Server(LocalBoxRequestValidator(), 600)

    def do_POST(self):  # pylint: disable=invalid-name
        logging.getLogger("oauth").debug("do_POST()")
        content_length = int(self.headers.getheader('Content-Length', 0))
        body = self.rfile.read(content_length)
	credentials=None
        try:
            headers, body, status = self.authserver.create_token_response(self.path, self.command, body, self.headers, credentials)
            self.send_response(status)
            for key, value in headers.iteritems():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)
        except OAuth2Error as error:
            if error.message:
                print "Message: " + error.message
            if error.description:
                print "Description: " + error.description
        
    def do_GET(self):  # pylint: disable=invalid-name
        """
        handle a HTTP GET request
        """
        logging.getLogger("oauth").debug("do_GET()")
        content_length = self.headers.getheader('Content-Length', 0)
        body = self.rfile.read(content_length)
        
        if self.path == "/verify":
            validity, request = self.authserver.verify_request(self.path, self.command, body, self.headers, None)
        try:
            scopes, credentials = self.authserver.validate_authorization_request(
                self.path, self.command, body, self.headers)
            # store credentials somewhere
            headers, body, status = self.authserver.create_authorization_response(self.path, self.command, body, self.headers, scopes, credentials)
            self.send_response(status)
            for key, value in headers.iteritems():
                self.send_header(key, value)
            self.end_headers()
        except OAuth2Error as error:
            print("OAuth2 Error: " + error.__class__.__name__ + ": " + error.error)
            if error.message:
                print "Message: " + error.message
            if error.description:
                print "Description: " + error.description
        return

def run():
    """
    start the test server.
    """
    logging.getLogger("oauth").debug("start program")
    server_address = ('127.0.0.1', 8000)
    httpd = HTTPServer(server_address, OAuth2HTTPRequestHandler)
    httpd.serve_forever()
    #httpd.handle_request()

if __name__ == '__main__':
    run()
