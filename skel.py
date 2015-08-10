"""
oauth implementation testing skeleton
"""
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from MySQLdb import connect
from MySQLdb import Error
from base64 import b64decode
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import WebApplicationServer
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError
from oauthlib.oauth2.rfc6749.errors import MissingClientIdError
from oauthlib.oauth2.rfc6749.errors import UnsupportedResponseTypeError
from oauthlib.oauth2.rfc6749.errors import UnauthorizedClientError


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
    def validate_client_id(self, client_id, request):
        """
        validates the client_id. Since this is either 'ios' or 'android', and
        this source code document is publicly available, the amount of
        security gained from this is practially none.
        """
        result = mysql_execute("select * from clients where id = " + client_id)
        return len(result) == 1

    def get_default_redirect_uri(self, client_id, request):
        """
        Redirect url for when none is given
        """
        return '/authenticated'

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """
        checks the validity of the response_type value.
        """
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
        return ''

    def validate_scopes(self, client_id, scopes, client, request, *args,
                        **kwargs):
        """
        validates validity of the given scope.
        """
        return True


def HTTPAuthenticate(authorization_header_contents):
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


class OAuth2HTTPRequestHandler(BaseHTTPRequestHandler):
    """
    handles oauth requests
    """
    def do_GET(self):
        """
        handle a HTTP GET request
        """
        print "HTTP GET start"
        authenticationheader = self.headers.getheader('Authorization')
        if authenticationheader != '':
            if HTTPAuthenticate(authenticationheader):
                print "Authentication successful."
        authserver = WebApplicationServer(LocalboxRequestValidator())
        content_length = self.headers.getheader('Content-Length', 0)
        body = self.rfile.read(content_length)
        try:
            result = authserver.validate_authorization_request(
                self.path, self.command, body, self.headers.dict)
            self.send_response(307)
            self.send_header('Location', self.headers.getheader(
                'redirect_uri', '/authenticated'))
            for key, value in result[1].iteritems():
                self.send_header(key, value)
            self.send_header("Content-type", "text/html")
            self.end_headers()
        except InvalidClientIdError as error:
            print error
            self.send_error(400, "Invalid client_id")
            self.send_header("Content-type", "text/html")
            self.end_headers()
        except MissingClientIdError as error:
            print error
            self.send_error(400, "Missing client_id")
            self.send_header("Content-type", "text/html")
            self.end_headers()
        except UnsupportedResponseTypeError as error:
            print error
            self.send_error(400, "Header response_type must be 'code'")
            # or others which the standard allow
            self.send_header("Content-type", "text/html")
            self.end_headers()
        except InvalidRequestError as error:
            print error
            self.send_error(400, "Sent response_type header invalid")
            self.send_header("Content-type", "text/html")
            self.end_headers()
        except UnauthorizedClientError as error:
            print error
            self.send_error(400, "Client not recognised as valid, " +
                            "possibly response_type has been malformed")
            self.send_header("Content-type", "text/html")
            self.end_headers()
        print "HTTP GET end"
        return


def run():
    """
    start the test server.
    """
    server_address = ('127.0.0.1', 8000)
    httpd = HTTPServer(server_address, OAuth2HTTPRequestHandler)
    print 'http server is running'
    httpd.serve_forever()

if __name__ == '__main__':
    run()
