LOauth - Oauth2 Compatible Autentication Module
===============================================

Install:
--------
The easiest method from this repository is as follows:
  python setup.py install

After installation, a configuration file needs to be created.
LOauth checks, in order, the following files: /etc/loauth.ini', '~/loauth.ini',
'~/.config/localbox/config.ini' and 'loauth.ini'.

The loauth.ini file needs to have a [database] section. This section needs a
'type' key with the value being either 'sqlite' or 'mysql'. In the case of
'mysql', the keys 'username', 'password', 'hostname', 'port' and 'database' are
to be configured. In case of sqlite, only a filename needs to be configured. An
example configuration for sqlite follows (make sure that the user running the
loauth program can actually edit that database:

[database]
type = sqlite
filename = /var/lib/loauth/database.sqlite3

Usage:
------
Run LOauth server
  python -m loauth
Initialise Database:
  python -m loauth --init-db
Add user:
  python -m loauth --add-user USERNAME PASSWORD
Delete user:
  python -m loauth --del-user USERNAME
Add client:
  python -m loauth --add-client CLIENT\_ID CLIENT\_SECRET USERNAME
Delete client:
  python -m loauth --del-client CLIENT\_ID
