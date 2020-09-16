import os
from app.base.handler import BaseHandler
from app.servers.models import ServersViewModel, Servers
from app.utils import encrypt, decrypt, read_file, get_current_time
from app.settings import base_dir


class ServersHandler(BaseHandler):

    def get(self,  *args, **kwargs):
        host_id = self.request.query_arguments.get('id')
        if not host_id:
            return self.finish({
                "code": "4001",
                "msg": "参数错误",
                "data": "name不能为空"
            })

        server_list = ServersViewModel.get_server_by_id(host_id[0])
        return self.finish({
            "code": "0000",
            "msg": "OK",
            "data": server_list.to_json()
        })

    # 添加主机
    def post(self, *args, **kwargs):
        name = self.json_dict.get("name")
        host = self.json_dict.get("host")
        port = self.json_dict.get("port")
        username = self.json_dict.get("username")
        password = self.json_dict.get("password")
        cn_password = self.json_dict.get("cn_password")

        if not name or name == "":
            return self.finish({
                "code": "4001",
                "msg": "参数错误",
                "data": "name不能为空"
            })
        if not host or host == "":
            return self.finish({
                "code": "4001",
                "msg": "参数错误",
                "data": "host不能为空"
            })
        if not port or port == "":
            return self.finish({
                "code": "4001",
                "msg": "参数错误",
                "data": "port不能为空"
            })
        if not username or username == "":
            return self.finish({
                "code": "4001",
                "msg": "参数错误",
                "data": "username不能为空"
            })
        if not password or password == "":
            return self.finish({
                "code": "4001",
                "msg": "参数错误",
                "data": "password不能为空"
            })
        if password != cn_password:
            return self.finish({
                "code": "4001",
                "msg": "参数错误",
                "data": "两次密码不一致"
            })
        server = ServersViewModel.get_server_by_name(name)
        if server:
            return self.finish({
                "code": "4001",
                "msg": "name已存在"
            })

        s = os.sep
        key = read_file(base_dir + s + "app" + s + "key" + s + "public.pem")
        new_password = encrypt(password, key)

        server = Servers()
        server.name = name
        server.host = host
        server.port = port
        server.username = username
        server.password = new_password
        server.create_dt = get_current_time()
        server.update_dt = get_current_time()
        server.status = 1
        ServersViewModel.add_server(server)

        return


class ServersListHandler(BaseHandler):

     def get(self,  *args, **kwargs):

        server_list = ServersViewModel.get_servers_list()
        return self.finish({
            "code": "0000",
            "msg": "OK",
            "data": [i.to_json() for i in server_list]
        })
