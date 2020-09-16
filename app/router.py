import os
from tornado.web import StaticFileHandler
from app.settings import base_dir
from app.servers.handler import ServersHandler
from app.ssh.handler import SshHandler
from app.websocket.handler import WsockHandler
from app.user.handler import LoginHandler


def make_urls(loop, policy, host_keys_settings):
    urls = [
        (r'/host_list', ServersHandler),
        # (r'/', BackHandler),
        (r'/login', LoginHandler),
        (r'/ssh', SshHandler, dict(loop=loop, policy=policy, host_keys_settings=host_keys_settings)),
        (r'/ssh/ws', WsockHandler, dict(loop=loop)),
        (r"/(.*)", StaticFileHandler,
         dict(path=os.path.join(base_dir, "templates"), default_filename="back.html"))
    ]
    return urls


