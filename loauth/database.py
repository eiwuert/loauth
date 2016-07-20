"""
Database implementation class
"""

from sqlite3 import Binary

from logging import getLogger
from os.path import exists
try:
    from ConfigParser import NoSectionError
except ImportError:
    from configparser import NoSectionError  # pylint: disable=F0401

try:
    from MySQLdb import connect as mysql_connect
    from MySQLdb import Error as MySQLError
except ImportError:
    mysql_connect = None

from sqlite3 import connect as sqlite_connect


from .config import ConfigSingleton

def get_sql_log_dict():
    parser = ConfigSingleton()
    dbtype = parser.get('database', 'type')
    if dbtype == 'sqlite':
        ip = parser.get('database', 'filename')
    else:
        ip = parser.get('database', 'hostname')
    return { 'ip': ip, 'user': '', 'path': 'database/' }

def database_execute(command, params=None):
    """
    Function to execute a sql statement on the database. Executes the right
    backend and makes sure '?' is replaced for the local substitution variable
    if needed.
    @param command the sql command to execute
    @param params a list of tuple of values to substitute in command
    @returns a list of dictionaries representing the sql result
    """
    getLogger("database").info("database_execute(" + command + ", " +
                                str(params) + ")", extra=get_sql_log_dict())
    parser = ConfigSingleton()
    dbtype = parser.get('database', 'type')

    if dbtype == "mysql":
        if mysql_execute is None:
            exit("Trying to use a MySQL database without python-MySQL module.")
        command = command.replace('?', '%s')
        return mysql_execute(command, params)

    elif (dbtype == "sqlite3") or (dbtype == "sqlite"):
        return sqlite_execute(command, params)
    else:
        getLogger(__name__).info("Unknown database type, cannot continue")


def sqlite_execute(command, params=None):
    """
    Function to execute a sql statement on the mysql database. This function is
    called by the database_execute function when the sqlite backend is set in
    the configuration file
    @param command the sql command to execute
    @param params a list of tuple of values to substitute in command
    @returns a list of dictionaries representing the sql result
    """
    # NOTE mostly copypasta'd from mysql_execute, may be a better way
    getLogger(__name__).debug("sqlite_execute(" + command + ", " +
                                str(params) + ")", extra=get_sql_log_dict())
    try:
        parser = ConfigSingleton()
        filename = parser.get('database', 'filename')
        init_db = not exists(filename)
        connection = sqlite_connect(filename)
        connection.text_factory = Binary
        cursor = connection.cursor()
        cursor.execute('PRAGMA foreign_keys = ON;')
        connection.commit()
        if cursor.fetchall() == None:
            exit("cannot do foreign keys on this SQLite database, exiting")
        if params:
            cursor.execute(command, params)
        else:
            cursor.execute(command)
        connection.commit()
        return cursor.fetchall()
    except MySQLError as mysqlerror:
        getLogger(__name__).info("MySQL Error: %d: %s" % (mysqlerror.args[0], mysqlerror.args[1]))
    except NoSectionError:
        getLogger(__name__).info("Please configure the database")
    finally:
        try:
            if connection:
                connection.close()
        except UnboundLocalError:
            pass


def mysql_execute(command, params=None):
    """
    Function to execute a sql statement on the mysql database. This function is
    called by the database_execute function when the mysql backend is set in
    the configuration file.
    @param command the sql command to execute
    @param params a list of tuple of values to substitute in command
    @returns a list of dictionaries representing the sql result
    """
    getLogger("database").debug("mysql_execute(" + command + ", " + str(params)
                                + ")", extra=get_sql_log_dict())
    parser = ConfigSingleton()
    try:
        host = parser.get('database', 'hostname')
        user = parser.get('database', 'username')
        pawd = parser.get('database', 'password')
        dbse = parser.get('database', 'database')
        port = parser.getint('database', 'port')
        connection = mysql_connect(host=host, port=port, user=user,
                                   passwd=pawd, db=dbse)
        cursor = connection.cursor()
        cursor.execute(command, params)
        connection.commit()
        return cursor.fetchall()
    except MySQLError as mysqlerror:
        getLogger(__name__).info("MySQL Error: %d: %s" % (mysqlerror.args[0], mysqlerror.args[1]))
    finally:
        try:
            if connection:
                connection.close()
        except UnboundLocalError:
            pass


def get_key_and_iv(localbox_path, user):
    """
    Fetches RSA encrypted key and IV from the database
    @param localbox_path (localbox specific) path to the encrypted file
    @param user name of whoes key to fetch
    @return a tuple containing the key and iv for a certain file.
    """
    sql = "select key, iv from keys where path = ? and user = ?"
    try:
        result = database_execute(sql, (localbox_path, user))[0]
    except(IndexError):
        getLogger("database").debug("cannot find key", extra={'ip': '', 'user': user, 'path': localbox_path})
        result = None
    return result
