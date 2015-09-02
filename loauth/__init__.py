"""
oauth implementation testing skeleton
"""
from json import dumps
from logging import getLogger
from logging import DEBUG
from logging import StreamHandler
from sys import exit

from ConfigParser import SafeConfigParser
from ConfigParser import NoSectionError
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from base64 import b64decode
from datetime import datetime, timedelta

from MySQLdb import connect
from MySQLdb import Error
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import Server
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from oauthlib.common import generate_client_id



class ClientStub:
    def __init__(self, client_id):
        self.client_id = client_id
    def __str__(self):
        return "Client: "+self.client_id

def mysql_execute(command, params = None):
    """
    Function to execute a sql statement on the mysql database
    """
    getLogger("oauth").debug("mysql_execute(" + command + ", " + str(params) + ")")
    try:
        parser = SafeConfigParser()
        parser.read(['/etc/loauth/config.ini', '~/.config/loauth/config.ini', './loauth.ini'])
        host = parser.get('database', 'hostname')
        user = parser.get('database', 'username')
        pawd = parser.get('database', 'password')
        dbse = parser.get('database', 'database')
        port = parser.getint('database', 'port')
        connection = connect(host=host, port=port, user=user, passwd=pawd, db=dbse)
        cursor = connection.cursor()
        cursor.execute(command, params)
        connection.commit()
        return cursor.fetchall()
    except Error as mysqlerror:
        print "MySQL Error: %d: %s" % (mysqlerror.args[0], mysqlerror.args[1])
    except NoSectionError:
        print "Please configure the database"
        exit(0)
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
    getLogger("oauth").debug("clear_bearer_tokens(" + client_id+")")
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
        getLogger("oauth").debug("validate_client_id(" + client_id + ")")
        result = mysql_execute("select * from clients where id = " + client_id)
        if result is None:
            return False
        return len(result) == 1

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """
        Redirect url for when none is given
        """
        getLogger("oauth").debug("get_default_redirect_uri(" + client_id + ")")
        return 'http://localhost:8000/authenticated'

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """
        TODO: check validity if redirect uri
        """
        getLogger("oauth").debug("validate_redirect_uri(" + client_id + ", " + redirect_uri + ")")
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        TODO: save authcode
        """
        getLogger("oauth").debug("save_authorization_code()")
	sql = "insert into authentication_code (client_id, authcode) values (%s, %s);"
        params = ( client_id, code['code'] )
        mysql_execute(sql, params)

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """
        checks the validity of the response_type value.
        """
        getLogger("oauth").debug("validate_response_type()")
        #TODO: filter certain response types because we cannot build certain things
        types = response_type.split(" ")
        return_value = True
        for rtype in types:
            if rtype not in ['code', 'token']:
                return_value = False
        return return_value

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """
        returns security scopes.
        """
        getLogger("oauth").debug("get_default_scopes(" + client_id + ")")
        return 'all'

    def validate_scopes(self, client_id, scopes, client, request, *args,
                        **kwargs):
        """
        validates validity of the given scope.
        """
        getLogger("oauth").debug("validate_scopes()")
        return True

    def validate_user(self, username, password, client, request, *args, **kwargs):
        getLogger("oauth").debug("validate_user(" + username + ", " + password + ", " + str(client) + ")")
        result = user_pass_authenticate(username, password)
        if result:
            self.user = username
            self.username = username
            sql = "select user from clients where id = %s"
            user = mysql_execute(sql, (client.client_id,))[0][0]
            if user is None:
                sql = "update clients set user = %s where id = %s"
                params = (username, client.client_id)
                mysql_execute(sql, params)
            else:
                result = (username == user)
        return result

    def authenticate_client(self, request, *args, **kwargs):
        getLogger("oauth").debug("authenticate_client()")
        authorization_header_contents = request.headers.get('authorization', '')
        if authorization_header_contents != '':
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
        getLogger("oauth").debug("authenticate_client_id()")
        raise NotImplementedError('needs checking')

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        getLogger("oauth").debug("get_original_scopes()")
        raise NotImplementedError('needs checking')
        return 'all'

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        getLogger("oauth").debug("invalidate_authorization_code()")
        sql = "delete from authentication_code where client_id = %s and authcode = %s;"
        mysql_execute(sql, (client_id, code))
        return

    def save_bearer_token(self, token, request, *args, **kwargs):
        getLogger("oauth").debug("save_bearer_token()")
        clear_bearer_tokens(request.client.client_id)

        sql = "insert into bearer_tokens (access_token, refresh_token, expires, scopes, client_id) values (%s, %s, %s, %s, %s)"
        enddate =  datetime.now() + timedelta(0,token['expires_in'],0,0,0,0)
        params = (token.get('access_token'), token.get('refresh_token'), enddate, token.get('scope'), request.client.client_id)
        mysql_execute(sql, params)

    def validate_bearer_token(self, token, scopes, request):
        getLogger("oauth").debug("validate_bearer_token()")
        sql = "select 1 from bearer_tokens where access_token = %s and client_id = %s and expires > NOW()";
        try:
            client_id = self.client.client_id
        except Error:
            client_id = None
        params = token, client_id
        result = mysql_execute(sql, params)
        if result is None:
            return False
        return len(result) == 1

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        getLogger("oauth").debug("validate_code()")
        #OBS! The request.user attribute should be set to the resource owner
        #associated with this authorization code. Similarly request.scopes and
        #request.state must also be set.
        #request.scopes="
        sql = "selectc 1 from code where client_id = %s and authcode = %s and expires > NOW();"
        result = mysql_execute(sql, (client_id, code))
        if result is None:
            return False
        return len(result)==1

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        getLogger("oauth").debug("validate_grant_type()")
        if (grant_type == 'client_credentials'):
            sql = "select user from clients where id = %s"
            user = mysql_execute(sql, (client.client_id,))[0][0]
            return user is not None
        else:
            return True

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        getLogger("oauth").debug("validate_refresh_token(" + refresh_token + ", " + client + ")")
        sql = "select 1 from bearer_tokens where refresh_token = %s and client_id = %s and expires > NOW()";
        params = refresh_token, client.client_id
        result = mysql_execute(sql, params)
        if result is None:
            return False
        return len(result) == 1


    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
            *args, **kwargs):
        getLogger("oauth").debug("confirm_redirect_uri()")
        raise NotImplementedError('needs checking')
        return True

def user_pass_authenticate(username, password, authenticate_client = False):
    getLogger("oauth").debug("user_pass_authenticate(" + username + ", " + password + ", " + str(authenticate_client) + ")")
    if authenticate_client:
        result = mysql_execute("select 1 from clients where id= %s and secret = %s;",
                           (username, password))
    else:
        result = mysql_execute("select 1 from users where user = %s and pass = %s;",
                           (username, password))
    if result is None:
        return False
    return len(result) == 1

def basic_http_authenticate(authorization_header_contents, authenticate_client=False):
    """
    Does (basic) HTTP authentication
    example line: Basic bmlkbzpwYXNzOm9yZA==
    NOTE: This implementation cannot handle usernames with colons.
    """
    getLogger("oauth").debug("basic_http_authenticate(" + authorization_header_contents+ ", " + str(authenticate_client) + ")")
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
        getLogger("oauth").debug("do_POST()")
        content_length = int(self.headers.getheader('Content-Length', 0))
        body = self.rfile.read(content_length)
	credentials = None
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
        getLogger("oauth").debug("do_GET()")
        content_length = self.headers.getheader('Content-Length', 0)
        body = self.rfile.read(content_length)
        
        if self.path == "/register":
            print "registring"
            client_id = generate_client_id()
            client_secret = generate_client_id()
            thingie = {'client_id': client_id, 'client_secret': client_secret}
            json = dumps(thingie)
            sql = 'insert into clients (id, secret) values (%s, %s);'
            mysql_execute(sql, (client_id, client_secret))
            self.wfile.write(json)
            return
        if self.path == "/verify":
            print "VERIFY PATH"
            auth_header_contents = self.headers.getheader('Authorization','')
            if auth_header_contents != '':
                ttype, token = auth_header_contents.split(' ')
                if ttype != 'Bearer':
                    result = "No Bearer Authorization Token found."
                    self.send_response(403)
                else:
                    sql = "select clients.user from bearer_tokens, clients where bearer_tokens.access_token = %s and bearer_tokens.expires > NOW() and bearer_tokens.client_id = clients.id;"
                    result = mysql_execute(sql, (token,))
                    if not result:
                        result = "No authenticated bearer authorization token found"
                        self.send_response(403)
                    else:
                        result = result[0][0]
                        self.send_response(200)
            else:
                result = False
                self.send_response(403)
            self.end_headers()
            print 'end'
            self.wfile.write(str(result))
            return
        else:
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
