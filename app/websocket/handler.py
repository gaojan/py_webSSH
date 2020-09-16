import json
import struct
import weakref
import logging
import paramiko
import tornado.web
from tornado.ioloop import IOLoop
from app.websocket.worker import clients
from app.base.handler import MixinHandler, InvalidValueError
from app.utils import UnicodeType
try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError


class WsockHandler(MixinHandler, tornado.websocket.WebSocketHandler):

    def initialize(self, loop):
        super(WsockHandler, self).initialize(loop)
        self.worker_ref = None

    def open(self):
        self.src_addr = self.get_client_addr()
        logging.info('Connected from {}:{}'.format(*self.src_addr))

        workers = clients.get(self.src_addr[0])
        if not workers:
            self.close(reason='Websocket authentication failed.')
            return

        try:
            worker_id = self.get_value('id')
        except (tornado.web.MissingArgumentError, InvalidValueError) as exc:
            self.close(reason=str(exc))
        else:
            worker = workers.get(worker_id)
            if worker:
                workers[worker_id] = None
                self.set_nodelay(True)
                worker.set_handler(self)
                self.worker_ref = weakref.ref(worker)
                self.loop.add_handler(worker.fd, worker, IOLoop.READ)
            else:
                self.close(reason='Websocket authentication failed.')

    def on_message(self, message):
        logging.debug('{!r} from {}:{}'.format(message, *self.src_addr))
        worker = self.worker_ref()
        try:
            msg = json.loads(message)
        except JSONDecodeError:
            return

        if not isinstance(msg, dict):
            return

        resize = msg.get('resize')
        if resize and len(resize) == 2:
            try:
                worker.chan.resize_pty(*resize)
            except (TypeError, struct.error, paramiko.SSHException):
                pass

        data = msg.get('data')
        if data and isinstance(data, UnicodeType):
            worker.data_to_dst.append(data)
            worker.on_write()

    def on_close(self):
        logging.info('Disconnected from {}:{}'.format(*self.src_addr))
        if not self.close_reason:
            self.close_reason = 'client disconnected'

        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close(reason=self.close_reason)
