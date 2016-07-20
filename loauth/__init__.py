"""
oauth implementation testing skeleton
"""
from json import dumps
from logging import getLogger
from urlparse import urlparse as parse
from hashlib import sha512
from os import urandom

from BaseHTTPServer import BaseHTTPRequestHandler
from base64 import b64decode
from base64 import b16encode
from datetime import datetime, timedelta

from MySQLdb import Error
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import Server
from oauthlib.oauth2.rfc6749.errors import OAuth2Error
from oauthlib.common import generate_client_id

from .database import database_execute

def create_database():
    for sql in ["PRAGMA foreign_keys = ON;",
                "create table users (user char(255) primary key, pass char(255), salt char(255));",
                "create table clients (id char(255) primary key, secret char(255), salt char(255), user char(255), foreign key(user) references users(user) on update cascade on delete cascade);",
                "create table authentication_code(client_id char(31), authcode char(31), foreign key(client_id) references clients(id) on update cascade on delete cascade);",
                "create table bearer_tokens(access_token char(31), refresh_token char(31), expires datetime, scopes char(255), client_id char(255), foreign key(client_id) references clients(id) on update cascade on delete cascade);"]:
        database_execute(sql)


def gethash(password, salt):
    passhash = sha512(str(salt) + password).hexdigest()
    return passhash

def addclient(client_id, client_secret, user=None, salt=None):
    sql = "insert into clients (id, secret, salt, user) values (?, ?, ?, ?);"
    if salt is None:
        salt = b16encode(urandom(8))
    passhash = gethash(client_secret, salt)
    database_execute(sql, (client_id, passhash, salt, user))

def listusers():
    sql = "select user from users;"
    result = [str(elem[0]) for elem in database_execute(sql)]
    
    return result

def listclients(user=None):
    sql = "select user, id from clients"
    if user != None:
        sql = sql + " where user = ?;"
        result = database_execute(sql, (user))
    else:
        result = database_execute(sql)
    users = {}
    for (user, client) in result:
        user = str(user)
        client = str(client)
        if user in users:
            users[user].append(client)
        else:
            users[user] = [client]
    return users
        

def adduser(username, password, salt=None):
    sql = "insert into users (user, pass, salt) values (?, ?, ?);"
    if salt is None:
        salt = b16encode(urandom(8))
    passhash = gethash(password, salt)
    database_execute(sql, (username, passhash, salt))

def moduser(username, password, salt=None):
    sql = "update users set pass=?, salt=? where user=?;"
    if salt is None:
        salt = b16encode(urandom(8))
    passhash = gethash(password, salt)
    database_execute(sql, (passhash, salt, username))
    
def modclient(username, password, salt=None):
    getLogger(__name__).debug("modclient(%s, %s, %s)", username, password, salt)
    sql = "update clients set secret = ?, salt = ? where id = ?;"
    if salt is None:
        salt = b16encode(urandom(8))
    passhash = gethash(password, salt)
    database_execute(sql, (passhash, salt, username))

def delclient(clientname):
    sql = "delete from clients where id = ?;"
    database_execute(sql, (clientname,))

def deluser(username):
    sql = "delete from users where user = ?;"
    database_execute(sql, (username,))
    sql = "delete from clients where user = ?;"
    database_execute(sql, (username,))

class ClientStub:
    def __init__(self, client_id):
        self.client_id = client_id
    def __str__(self):
        return "Client: "+self.client_id

def clear_bearer_tokens(client_id):
    """
    remove excess tokens
    """
    getLogger(__name__).debug("clear_bearer_tokens(" + client_id+")")
    sql = "delete from bearer_tokens where client_id = ?;"
    database_execute(sql, (client_id, ))

class LoauthRequestValidator(RequestValidator):
    """
    Checks correctness of the various aspects of the oauthlib server
    """
    def __init__(self, *args, **kwargs):
        self.username = None
        self.user = None
        self.name = None 
        self.client = None
        RequestValidator.__init__(self, *args, **kwargs)

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        validates the client_id. Since this is either 'ios' or 'android', and
        this source code document is publicly available, the amount of
        security gained from this is practially none.
        """
        getLogger(__name__).debug("validate_client_id(" + client_id + ")")
        result = database_execute("select * from clients where id = " + client_id)
        if result is None:
            return False
        return len(result) == 1

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """
        Redirect url for when none is given
        """
        getLogger(__name__).debug("get_default_redirect_uri(" + client_id + ")")
        return 'http://localhost:8000/authenticated'

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """
        TODO: check validity if redirect uri
        """
        getLogger(__name__).debug("validate_redirect_uri(" + client_id + ", " + redirect_uri + ")")
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        TODO: save authcode
        """
        getLogger(__name__).debug("save_authorization_code()")
        sql = "insert into authentication_code (client_id, authcode) values (?, ?);"
        params = (client_id, code['code'])
        database_execute(sql, params)

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """
        checks the validity of the response_type value.
        """
        getLogger(__name__).debug("validate_response_type()")
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
        getLogger(__name__).debug("get_default_scopes(" + client_id + ")")
        return 'all'

    def validate_scopes(self, client_id, scopes, client, request, *args,
                        **kwargs):
        """
        validates validity of the given scope.
        """
        getLogger(__name__).debug("validate_scopes()")
        return True

    def validate_user(self, username, password, client, request, *args, **kwargs):
        getLogger(__name__).debug("validate_user(" + username + ", " + password + ", " + str(client) + ")")
        result = user_pass_authenticate(username, password)
        if result:
            self.user = username
            self.username = username
            sql = "select user from clients where id = ?"
            user = database_execute(sql, (client.client_id,))[0][0]
            if user is None:
                sql = "update clients set user = ? where id = ?"
                params = (username, client.client_id)
                database_execute(sql, params)
            else:
                result = (username == user)
        return result

    def authenticate_client(self, request, *args, **kwargs):
        getLogger(__name__).debug("authenticate_client()")
        bodydict = dict(request.decoded_body)
        if ((request.headers.get('username', '') != '' and
           request.headers.get('password', '') != '' and
           request.headers.get('grant_type', '') == 'password') or
           (bodydict.get('username') != None and
           bodydict.get('password') != None and
           bodydict.get('grant_type') == 'password')):

            getLogger(__name__).info("This is a localbox special situation. Adding Client based on user/pass")
            client_id = request.headers.get('client_id', bodydict.get('client_id'))
            sql = "select 1 from clients where id = ?;"
            result = database_execute(sql, (client_id,))
            if result == []:
                getLogger(__name__).info("client not found")
                request.client_id = client_id
                request.client = ClientStub(client_id)
                client_secret = request.headers.get('client_secret', bodydict.get('client_secret'))
                addclient(client_id, client_secret)
                return True
            return False

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
            username = dict(request.decoded_body)['client_id']
            password = dict(request.decoded_body)['client_secret']
            result = user_pass_authenticate(username, password, True)
            if result:
                request.client_id = username
                request.client = ClientStub(username)
            return result

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        getLogger(__name__).debug("authenticate_client_id()")
        raise NotImplementedError('needs checking')

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        getLogger(__name__).debug("get_original_scopes()")
        return 'all'

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        getLogger(__name__).debug("invalidate_authorization_code()")
        sql = "delete from authentication_code where client_id = ? and authcode = ?;"
        database_execute(sql, (client_id, code))
        return

    def save_bearer_token(self, token, request, *args, **kwargs):
        getLogger(__name__).debug("save_bearer_token()")
        clear_bearer_tokens(request.client.client_id)

        sql = "insert into bearer_tokens (access_token, refresh_token, expires, scopes, client_id) values (?, ?, ?, ?, ?)"
        enddate =  datetime.now() + timedelta(0, token['expires_in'], 0, 0, 0, 0)
        params = (token.get('access_token'), token.get('refresh_token'), enddate, token.get('scope'), request.client.client_id)
        database_execute(sql, params)

    def validate_bearer_token(self, token, scopes, request):
        getLogger(__name__).debug("validate_bearer_token()")
        sql = "select 1 from bearer_tokens where access_token = ? and client_id = ? and expires > datetime('now');"
        try:
            client_id = self.client.client_id
        except Error:
            client_id = None
        params = token, client_id
        result = database_execute(sql, params)
        if result is None:
            return False
        return len(result) == 1

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        getLogger(__name__).debug("validate_code()")
        #OBS! The request.user attribute should be set to the resource owner
        #associated with this authorization code. Similarly request.scopes and
        #request.state must also be set.
        #request.scopes="
        sql = "selectc 1 from code where client_id = ? and authcode = ? and expires > datetime('now');"
        result = database_execute(sql, (client_id, code))
        if result is None:
            return False
        return len(result)==1

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        getLogger(__name__).debug("validate_grant_type()")
        if (grant_type == 'client_credentials'):
            sql = "select user from clients where id = ?"
            user = database_execute(sql, (client.client_id,))[0][0]
            return user is not None
        else:
            return True

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        getLogger(__name__).debug("validate_refresh_token(" + refresh_token + ", " + client + ")")
        sql = "select 1 from bearer_tokens where refresh_token = ? and client_id = ? and expires > datetime('now');"
        params = refresh_token, client.client_id
        result = database_execute(sql, params)
        if result is None:
            return False
        return len(result) == 1


    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
            *args, **kwargs):
        getLogger(__name__).debug("confirm_redirect_uri()")
        return True

def user_pass_authenticate(username, password, authenticate_client = False):
    getLogger(__name__).debug("user_pass_authenticate(" + username + ", " + password + ", " + str(authenticate_client) + ")")
    if authenticate_client:
        result = database_execute("select secret, salt from clients where id = ?;", (username,))
    else:
        result = database_execute("select pass, salt from users where user = ?;", (username,))
    if result == []:
        getLogger(__name__).debug("Cannot find user %s to authenticate.", username)
        return False
    else:
        passhash = str(result[0][0])
        salt = result[0][1]
        calchash = gethash(password, salt)
        success = passhash == calchash
        if success:
            getLogger(__name__).debug("Authentication successful")
        else:
            getLogger(__name__).debug("Authentication failed due to wrong password")
        return success

def basic_http_authenticate(authorization_header_contents, authenticate_client=False):
    """
    Does (basic) HTTP authentication
    example line: Basic bmlkbzpwYXNzOm9yZA==
    NOTE: This implementation cannot handle usernames with colons.
    """
    getLogger(__name__).debug("basic_http_authenticate(" + authorization_header_contents+ ", " + str(authenticate_client) + ")")
    if authorization_header_contents is None:
        return False
    try:
        authtype, authdata = authorization_header_contents.split(" ")
        assert authtype == "Basic"
    except(ValueError, AssertionError) as error:
        getLogger(__name__).info("Cannot authenticate: %s", error.message)
        return False
    data = b64decode(authdata)
    username, password = data.split(":", 1)
    return user_pass_authenticate(username, password, authenticate_client=authenticate_client)

class OAuth2HTTPRequestHandler(BaseHTTPRequestHandler):
    """
    handles oauth requests
    """

    authserver = Server(LoauthRequestValidator(), 600)

    def do_POST(self):  # pylint: disable=invalid-name
        getLogger(__name__).debug("do_POST()")
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
                self.wfile.write(error.message)
                getLogger(__name__).info("Message: %s", error.message)
            if error.description:
                self.wfile.write(error.description)
                getLogger(__name__).info("Description: %s", error.description)
        
    def do_GET(self):  # pylint: disable=invalid-name
        """
        handle a HTTP GET request
        """
        getLogger(__name__).debug("do_GET()")
        content_length = self.headers.getheader('Content-Length', 0)
        body = self.rfile.read(content_length)
        
        parsed_path = parse(self.path).path
        #if parsed_path == "/register":
        #    print "registring"
        #    client_id = generate_client_id()
        #    client_secret = generate_client_id()
        #    thingie = {'client_id': client_id, 'client_secret': client_secret}
        #    json = dumps(thingie)
        #    sql = 'insert into clients (id, secret) values (?, ?);'
        #    database_execute(sql, (client_id, client_secret))
        #    self.wfile.write(json)
        #    return
        if parsed_path == "/verify":
            getLogger(__name__).debug("Verify path")
            auth_header_contents = self.headers.getheader('Authorization','')
            if auth_header_contents != '':
                try:
                    ttype, token = auth_header_contents.split(' ')
                except ValueError:
                    getLogger(__name__).critical("Problem parsing authorization header: %s", auth_header_contents)
                    self.send_response(403)
                    return
                if ttype != 'Bearer':
                    result = "No Bearer Authorization Token found."
                    self.send_response(403)
                else:
                    sql = "select clients.user from bearer_tokens, clients where bearer_tokens.access_token = ? and bearer_tokens.expires > datetime('now') and bearer_tokens.client_id = clients.id;"
                    result = database_execute(sql, (token,))
                    if not result:
                        result = "No authenticated bearer authorization token found"
                        self.send_response(403)
                    else:
                        result = result[0][0]
                        self.send_response(200)
            else:
                result = None
                self.send_response(403)
            self.end_headers()
            getLogger(__name__).debug('end')
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
                getLogger(__name__).critical("OAuth2 Error: %s: %s", error.__class__.__name__, error.error)
                if error.message:
                    self.wfile.write(error.message)
                    getLogger(__name__).debug("Message: %s", error.message)
                if error.description:
                    self.wfile.write(error.description)
                    getLogger(__name__).debug("Description: %s", error.description)
        return
