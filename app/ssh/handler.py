import io
import logging
import socket
import traceback
import paramiko
import tornado.web
from concurrent.futures import ThreadPoolExecutor
from tornado.options import options
from tornado.process import cpu_count
from app.utils import (is_valid_ip_address, is_valid_port, is_valid_hostname, to_bytes, to_str, to_int)
from app.base.handler import MixinHandler
from app.websocket.worker import Worker, recycle_worker, clients

DELAY = 3
DEFAULT_PORT = 22
swallow_http_errors = True


class InvalidValueError(Exception):
    pass


class SSHClient(paramiko.SSHClient):

    def handler(self, title, instructions, prompt_list):
        answers = []
        for prompt_, _ in prompt_list:
            prompt = prompt_.strip().lower()
            if prompt.startswith('password'):
                answers.append(self.password)
            elif prompt.startswith('verification'):
                answers.append(self.totp)
            else:
                raise ValueError('Unknown prompt: {}'.format(prompt_))
        return answers

    def auth_interactive(self, username, handler):
        if not self.totp:
            raise ValueError('Need a verification code for 2fa.')
        self._transport.auth_interactive(username, handler)

    def _auth(self, username, password, pkey, *args):
        self.password = password
        saved_exception = None
        two_factor = False
        allowed_types = set()
        two_factor_types = {'keyboard-interactive', 'password'}

        if pkey is not None:
            logging.info('Trying publickey authentication')
            try:
                allowed_types = set(
                    self._transport.auth_publickey(username, pkey)
                )
                two_factor = allowed_types & two_factor_types
                if not two_factor:
                    return
            except paramiko.SSHException as e:
                saved_exception = e

        if two_factor:
            logging.info('Trying publickey 2fa')
            return self.auth_interactive(username, self.handler)

        if password is not None:
            logging.info('Trying password authentication')
            try:
                self._transport.auth_password(username, password)
                return
            except paramiko.SSHException as e:
                saved_exception = e
                allowed_types = set(getattr(e, 'allowed_types', []))
                two_factor = allowed_types & two_factor_types

        if two_factor:
            logging.info('Trying password 2fa')
            return self.auth_interactive(username, self.handler)

        assert saved_exception is not None
        raise saved_exception


class PrivateKey(object):

    max_length = 16384  # rough number

    tag_to_name = {
        'RSA': 'RSA',
        'DSA': 'DSS',
        'EC': 'ECDSA',
        'OPENSSH': 'Ed25519'
    }

    def __init__(self, privatekey, password=None, filename=''):
        self.privatekey = privatekey
        self.filename = filename
        self.password = password
        self.check_length()
        self.iostr = io.StringIO(privatekey)

    def check_length(self):
        if len(self.privatekey) > self.max_length:
            raise InvalidValueError('Invalid key length.')

    def parse_name(self, iostr, tag_to_name):
        name = None
        for line_ in iostr:
            line = line_.strip()
            if line and line.startswith('-----BEGIN ') and \
                    line.endswith(' PRIVATE KEY-----'):
                lst = line.split(' ')
                if len(lst) == 4:
                    tag = lst[1]
                    if tag:
                        name = tag_to_name.get(tag)
                        if name:
                            break
        return name, len(line_)

    def get_pkey_obj(self):
        name, length = self.parse_name(self.iostr, self.tag_to_name)
        if not name:
            raise InvalidValueError('Invalid key {}.'.format(self.filename))

        offset = self.iostr.tell() - length
        self.iostr.seek(offset)
        logging.debug('Reset offset to {}.'.format(offset))

        logging.info('Parsing {} key'.format(name))
        pkeycls = getattr(paramiko, name+'Key')
        password = to_bytes(self.password) if self.password else None

        try:
            return pkeycls.from_private_key(self.iostr, password=password)
        except paramiko.PasswordRequiredException:
            raise InvalidValueError('Need a password to decrypt the key.')
        except paramiko.SSHException as exc:
            logging.error(str(exc))
            msg = 'Invalid key'
            if self.password:
                msg += ' or wrong password "{}" for decrypting it.'.format(
                        self.password)
            raise InvalidValueError(msg)


class BackHandler(MixinHandler, tornado.web.RequestHandler):

    def __init__(self, application, request, **kwargs):
        super(BackHandler, self).__init__(application, request, **kwargs)

    def get(self):
        self.render('back.html')


class SshHandler(MixinHandler, tornado.web.RequestHandler):

    executor = ThreadPoolExecutor(max_workers=cpu_count()*5)

    def initialize(self, loop, policy, host_keys_settings):
        super(SshHandler, self).initialize(loop)
        self.policy = policy
        self.host_keys_settings = host_keys_settings
        self.ssh_client = self.get_ssh_client()
        self.debug = self.settings.get('debug', False)
        self.result = dict(id=None, status=None, encoding=None)

    def write_error(self, status_code, **kwargs):
        if swallow_http_errors and self.request.method == 'POST':
            exc_info = kwargs.get('exc_info')
            if exc_info:
                reason = getattr(exc_info[1], 'log_message', None)
                if reason:
                    self._reason = reason
            self.result.update(status=self._reason)
            self.set_status(200)
            self.finish(self.result)
        else:
            super(SshHandler, self).write_error(status_code, **kwargs)

    def get_ssh_client(self):
        ssh = SSHClient()
        ssh._system_host_keys = self.host_keys_settings['system_host_keys']
        ssh._host_keys = self.host_keys_settings['host_keys']
        ssh._host_keys_filename = self.host_keys_settings['host_keys_filename']
        ssh.set_missing_host_key_policy(self.policy)
        return ssh

    def get_privatekey(self):
        name = 'privatekey'
        lst = self.request.files.get(name)
        if lst:
            # multipart form
            filename = lst[0]['filename']
            data = lst[0]['body']
            value = self.decode_argument(data, name=name).strip()
        else:
            # urlencoded form
            value = self.get_argument(name, u'')
            filename = ''

        return value, filename

    def get_hostname(self):
        value = self.get_value('hostname')
        if not (is_valid_hostname(value) or is_valid_ip_address(value)):
            raise InvalidValueError('Invalid hostname: {}'.format(value))
        return value

    def get_port(self):
        value = self.get_argument('port', u'')
        if not value:
            return DEFAULT_PORT

        port = to_int(value)
        if port is None or not is_valid_port(port):
            raise InvalidValueError('Invalid port: {}'.format(value))
        return port

    def lookup_hostname(self, hostname, port):
        key = hostname if port == 22 else '[{}]:{}'.format(hostname, port)

        if self.ssh_client._system_host_keys.lookup(key) is None:
            if self.ssh_client._host_keys.lookup(key) is None:
                raise tornado.web.HTTPError(
                        403, 'Connection to {}:{} is not allowed.'.format(
                            hostname, port)
                    )

    def get_args(self):
        hostname = self.get_hostname()
        port = self.get_port()
        username = self.get_value('username')
        password = self.get_argument('password', u'')
        privatekey, filename = self.get_privatekey()
        passphrase = self.get_argument('passphrase', u'')
        totp = self.get_argument('totp', u'')

        if isinstance(self.policy, paramiko.RejectPolicy):
            self.lookup_hostname(hostname, port)

        if privatekey:
            pkey = PrivateKey(privatekey, passphrase, filename).get_pkey_obj()
        else:
            pkey = None

        self.ssh_client.totp = totp
        args = (hostname, port, username, password, pkey)
        logging.debug(args)

        return args

    def get_default_encoding(self, ssh):
        try:
            _, stdout, _ = ssh.exec_command('locale charmap')
        except paramiko.SSHException:
            result = None
        else:
            result = to_str(stdout.read().strip())

        return result if result else 'utf-8'

    def ssh_connect(self, args):
        ssh = self.ssh_client
        dst_addr = args[:2]
        logging.info('Connecting to {}:{}'.format(*dst_addr))

        try:
            ssh.connect(*args, timeout=6)
        except socket.error:
            raise ValueError('Unable to connect to {}:{}'.format(*dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('Bad authentication type.')
        except paramiko.AuthenticationException:
            raise ValueError('Authentication failed.')
        except paramiko.BadHostKeyException:
            raise ValueError('Bad host key.')

        chan = ssh.invoke_shell(term='xterm')
        chan.setblocking(0)
        worker = Worker(self.loop, ssh, chan, dst_addr)
        worker.encoding = self.get_default_encoding(ssh)
        return worker

    def check_origin(self):
        event_origin = self.get_argument('_origin', u'')
        header_origin = self.request.headers.get('Origin')
        origin = event_origin or header_origin

        if origin:
            if not super(SshHandler, self).check_origin(origin):
                raise tornado.web.HTTPError(
                    403, 'Cross origin operation is not allowed.'
                )

            if not event_origin and self.origin_policy != 'same':
                self.set_header('Access-Control-Allow-Origin', origin)

    def head(self):
        pass

    def get(self):
        self.render('index.html', debug=self.debug)

    @tornado.gen.coroutine
    def post(self):
        if self.debug and self.get_argument('error', u''):
            # for testing purpose only
            raise ValueError('Uncaught exception')

        ip, port = self.get_client_addr()
        workers = clients.get(ip, {})
        if workers and len(workers) >= options.maxconn:
            raise tornado.web.HTTPError(403, 'Too many live connections.')

        self.check_origin()

        try:
            args = self.get_args()
        except InvalidValueError as exc:
            raise tornado.web.HTTPError(400, str(exc))

        future = self.executor.submit(self.ssh_connect, args)

        try:
            worker = yield future
        except (ValueError, paramiko.SSHException) as exc:
            logging.error(traceback.format_exc())
            self.result.update(status=str(exc))
        else:
            if not workers:
                clients[ip] = workers
            worker.src_addr = (ip, port)
            workers[worker.id] = worker
            self.loop.call_later(DELAY, recycle_worker, worker)
            self.result.update(id=worker.id, encoding=worker.encoding)

        self.write(self.result)


