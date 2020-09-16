import json
import logging
import tornado.web
from datetime import datetime
from app.database import get_token_info, refresh_token
from tornado.web import RequestHandler, Finish
from tornado.options import options
from app.utils import (is_valid_port, to_int, to_ip_address, is_ip_hostname, is_same_primary_domain)

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

redirecting = None


class BaseHandler(RequestHandler):

    def __init__(self, application, request, **kwargs):
        self.json_dict = {}
        super(BaseHandler, self).__init__(application, request, **kwargs)

    def prepare(self):
        """ 请求前预处理"""
        # 允许json格式参数
        if not 'GET' == self.request.method and ('application/json' != self.request.headers.get('Content-Type')):
            raise Finish({'code': "400", 'msg': "json error"})
        if not 'GET' == self.request.method and 'application/json' == self.request.headers.get('Content-Type'):
            try:
                if self.request.body:
                    self.json_dict = json.loads(self.request.body)
            except JSONDecodeError:
                raise Finish({"code": "400", "msg": "json error"})

    def data_received(self, chunk):
        return

    def options(self, *args, **kwargs):
        return self.set_status(200)

    def write_error(self, status_code, **kwargs):
        if 500 == status_code:
            self.set_status(500)
            return self.finish({'code': "500", 'msg': "内部错误"})
        if 405 == status_code:
            self.set_status(405)
            return self.finish({'code': "405", 'msg': "未知错误"})

    def on_finish(self):
        pass

    def get_current_user(self):
        access_token_list = self.request.headers.get_list('Access-Token')
        if not access_token_list:
            return None
        access_token = access_token_list[0]
        user_id, expiration = get_token_info(access_token)
        if not user_id:
            return None
        # 验证是否过期
        if datetime.now() > expiration:
            return None
        count = self.cursor.execute("select * from t_user where id={}".format(user_id))
        user = list(self.cursor.fetchone())
        if user is None:
            return None
        refresh_token(user_id)  # 更新token过期时间
        return user


class InvalidValueError(Exception):
    pass


class MixinHandler(object):

    custom_headers = {
        'Server': 'TornadoServer'
    }

    html = ('<html><head><title>{code} {reason}</title></head><body>{code} '
            '{reason}</body></html>')

    def initialize(self, loop=None):
        self.check_request()
        self.loop = loop
        self.origin_policy = self.settings.get('origin_policy')

    def check_request(self):
        context = self.request.connection.context
        result = self.is_forbidden(context, self.request.host_name)
        self._transforms = []
        if result:
            self.set_status(403)
            self.finish(
                self.html.format(code=self._status_code, reason=self._reason)
            )
        elif result is False:
            to_url = self.get_redirect_url(
                self.request.host_name, options.sslport, self.request.uri
            )
            self.redirect(to_url, permanent=True)
        else:
            self.context = context

    def check_origin(self, origin):
        if self.origin_policy == '*':
            return True

        parsed_origin = urlparse(origin)
        netloc = parsed_origin.netloc.lower()
        logging.debug('netloc: {}'.format(netloc))

        host = self.request.headers.get('Host')
        logging.debug('host: {}'.format(host))

        if netloc == host:
            return True

        if self.origin_policy == 'same':
            return False
        elif self.origin_policy == 'primary':
            return is_same_primary_domain(netloc.rsplit(':', 1)[0],
                                          host.rsplit(':', 1)[0])
        else:
            return origin in self.origin_policy

    def is_forbidden(self, context, hostname):
        ip = context.address[0]
        lst = context.trusted_downstream
        ip_address = None

        if lst and ip not in lst:
            logging.warning(
                'IP {!r} not found in trusted downstream {!r}'.format(ip, lst)
            )
            return True

        if context._orig_protocol == 'http':
            if redirecting and not is_ip_hostname(hostname):
                ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    # redirecting
                    return False

            if options.fbidhttp:
                if ip_address is None:
                    ip_address = to_ip_address(ip)
                if not ip_address.is_private:
                    logging.warning('Public plain http request is forbidden.')
                    return True

    def get_redirect_url(self, hostname, port, uri):
        port = '' if port == 443 else ':%s' % port
        return 'https://{}{}{}'.format(hostname, port, uri)

    def set_default_headers(self):
        for header in self.custom_headers.items():
            self.set_header(*header)

    def get_value(self, name):
        value = self.get_argument(name)
        if not value:
            raise InvalidValueError('Missing value {}'.format(name))
        return value

    def get_client_addr(self):
        if options.xheaders:
            return self.get_real_client_addr() or self.context.address
        else:
            return self.context.address

    def get_real_client_addr(self):
        ip = self.request.remote_ip

        if ip == self.request.headers.get('X-Real-Ip'):
            port = self.request.headers.get('X-Real-Port')
        elif ip in self.request.headers.get('X-Forwarded-For', ''):
            port = self.request.headers.get('X-Forwarded-Port')
        else:
            # not running behind an nginx server
            return

        port = to_int(port)
        if port is None or not is_valid_port(port):
            # fake port
            port = 65535

        return (ip, port)


class NotFoundHandler(MixinHandler, tornado.web.ErrorHandler):

    def initialize(self):
        super(NotFoundHandler, self).initialize()

    def prepare(self):
        raise tornado.web.HTTPError(404)

    def data_received(self, chunk):
        return



