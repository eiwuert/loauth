from MySQLdb import connect
from MySQLdb import Error
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
from oauthlib.oauth2 import RequestValidator
from oauthlib.oauth2 import WebApplicationServer
from oauthlib.oauth2.rfc6749.errors import InvalidClientIdError
from oauthlib.oauth2.rfc6749.errors import InvalidRequestError
from oauthlib.oauth2.rfc6749.errors import MissingClientIdError
from oauthlib.oauth2.rfc6749.errors import UnsupportedResponseTypeError
from oauthlib.oauth2.rfc6749.errors import UnauthorizedClientError
from sys import exit
from base64 import b64decode

def mysql_execute(command):
	try:
		connection = connect('localhost', 'user', 'pass', 'test')
		cursor = connection.cursor()
		cursor.execute(command)
		return cursor.fetchall()
	except Error, e:
		print "MySQL Error: %d: %s\n" % (e.args[0], e.args[1])
		exit(1)
	finally:
		if connection:
			connection.close()


class LocalboxRequestValidator(RequestValidator):
	def validate_client_id(self, client_id, request):
		# validates the client_id. Since this is either 'ios' or 'android', and this
		# source code document is publicly available, the amount of security gained
		# from this is practially none.
		result = mysql_execute("select * from clients where id = " + client_id)
		return (len(result) == 1)

	def get_default_redirect_uri(self, client_id, request):
		return '/authenticated'

	def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
		types = response_type.split(" ")
		return_value = True
		for rtype in types:
			if not rtype in ['code', 'token']:
				return_value = False
				print "falsified response type"
		return return_value

	def get_default_scopes(self, client_id, request, *args, **kwargs):
		return ''

	def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
		return True

def HTTPAuthenticate(authorization_header_contents):
	# example line: Basic bmlkbzpwYXNzOm9yZA==
	# NOTE: this authentication implementation cannot handle usernames with colons.
	authtype, authdata = authorization_header_contents.split(" ");
	data = b64decode(authdata)
	username, password = data.split(":",1)
	#TODO: Not this
	result = mysql_execute("select * from users where name = '" + username + "' and pass = '" + password + "';")
	return(len(result) == 1)

class OAuth2HTTPRequestHandler(BaseHTTPRequestHandler):
	def do_GET(self):
		authenticationheader = self.headers.getheader('Authorization')
		if authenticationheader != '':
			if HTTPAuthenticate(authenticationheader):
				print "Authentication successful. Now to intergrate it with the rest"
		authserver = WebApplicationServer(LocalboxRequestValidator())
		content_length = self.headers.getheader('Content-Length',0)
		body = self.rfile.read(content_length)
		print "GETTINGUH"
		try:
			result = authserver.validate_authorization_request(self.path, self.command, body, self.headers.dict)
			self.send_response(307)
			self.send_header('Location', self.headers.getheader('redirect_uri', '/authenticated')) # TODO default value?
			for key, value in result[1].iteritems():
				self.send_header(key, value)
			self.send_header("Content-type", "text/html")
			self.end_headers()
		except InvalidClientIdError as e:
			self.send_error(400, "Invalid client_id")
			self.send_header("Content-type", "text/html")
			self.end_headers()
		except MissingClientIdError as e:
			self.send_error(400, "Missing client_id")
			self.send_header("Content-type", "text/html")
			self.end_headers()
		except UnsupportedResponseTypeError as e:
			self.send_error(400, "Header response_type must be 'code'") #or others which the standard allow
			self.send_header("Content-type", "text/html")
			self.end_headers()
		except InvalidRequestError as e:
			self.send_error(400, "Sent response_type header invalid")
			self.send_header("Content-type", "text/html")
			self.end_headers()
		except UnauthorizedClientError as e:
			self.send_error(400, "Client not recognised as valid, possibly response_type has been malformed")
			self.send_header("Content-type", "text/html")
			self.end_headers()

		print "DONNU GET"
		return

def run():
	server_address = ('127.0.0.1', 8000)
	httpd = HTTPServer(server_address, OAuth2HTTPRequestHandler)
	print('http server is running')
	httpd.serve_forever()

if __name__ == '__main__':
	run()
