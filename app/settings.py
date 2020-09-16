import os.path
import sys
from tornado.options import define
from _version import __version__


# mysql
MYSQL = {
    'ip': '192.168.0.220',
    'port': '3306',
    'database': 'web_ssh',
    'user': 'xrt',
    'password': 'xrt@qq.com'
}

# redis
REDIS = {
    'host': '192.168.0.220',
    'port': 6379
}

# token
TOKEN_EXPIRATION = 86400  # 过期时间，秒
TOKEN_USER_KEY = 'ssh_token'  # token作field，userid和过期时间作value
USER_TOKEN_KEY = 'ssh_user'  # userid作field，token和sessionkey作value
TOKEN_CONNECTOR = '@'  # redis里token相关信息的连接符

# host密码加密Key
KEY = "16eb91b035f2d8f11b4f1fa3501aa9c5df5295f4"


def print_version(flag):
    if flag:
        print(__version__)
        sys.exit(0)


define('address', default='0.0.0.0', help='Listen address')
define('port', type=int, default=8888,  help='Listen port')
define('ssladdress', default='0.0.0.0', help='SSL listen address')
define('sslport', type=int, default=4433,  help='SSL listen port')
define('certfile', default='', help='SSL certificate file')
define('keyfile', default='', help='SSL private key file')
define('debug', type=bool, default=True, help='Debug mode')
define('policy', default='warning',
       help='Missing host key policy, reject|autoadd|warning')
define('hostfile', default='', help='User defined host keys file')
define('syshostfile', default='', help='System wide host keys file')
define('tdstream', default='', help='Trusted downstream, separated by comma')
define('redirect', type=bool, default=True, help='Redirecting http to https')
define('fbidhttp', type=bool, default=True,
       help='Forbid public plain http incoming requests')
define('xheaders', type=bool, default=True, help='Support xheaders')
define('xsrf', type=bool, default=False, help='CSRF protection')  # 生产环境需改回来
define('origin', default='same', help='''Origin policy,
'same': same origin policy, matches host name and port number;
'primary': primary domain policy, matches primary domain only;
'<domains>': custom domains policy, matches any domain in the <domains> list
separated by comma;
'*': wildcard policy, matches any domain, allowed in debug mode only.''')
define('wpintvl', type=int, default=0, help='Websocket ping interval')
define('maxconn', type=int, default=20,
       help='Maximum live connections (ssh sessions) per client')
define('version', type=bool, help='Show version information',
       callback=print_version)


base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
max_body_size = 1 * 1024 * 1024


