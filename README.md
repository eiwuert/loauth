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

```ini
[database]
type = sqlite
filename = /var/lib/loauth/database.sqlite3
```

Usage:
------
* Run LOauth server:
  `python -m loauth`
* Help for additional options:
  `python -m loauth -h`
* Initialise Database:
  `python -m loauth --init-db`
* Add user:
  `python -m loauth --add-user USERNAME [--password PASSWORD]`
* Delete user:
  `python -m loauth --del-user USERNAME`
* Change user password:
  `python -m loauth --mod-user USERNAME [--password PASSWORD]`
* Test user authentication:
  `python -m loauth --authenticateuser USERNAME [--password PASSWORD]`
* Add client:
  `python -m loauth --add-client CLIENT\_ID USERNAME [--password CLIENT\_SECRET]`
* Change client secret:
  `python -m loauth --mod-client CLIENT\_ID [--password CLIENT\_SECRET]`
* Delete client:
  `python -m loauth --del-client CLIENT\_ID`
* Test client authentication:
  `python -m loauth --authenticateclient CLIENT\_ID [--password CLIENT\_SECRET]`


The '--password' argument is optional. Not providing it where it is listed in
these examples will make LOauth use getpass to extract said password from the
terminal instead. Use of the --password parameter is discouraged because shell
commands are usually logged in a .bash\_history file, and using the --password
call will then store the password in plain text in said file.

