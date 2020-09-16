from app.base.handler import BaseHandler


class LoginHandler(BaseHandler):

    def post(self, *args, **kwargs):
        account = self.get_argument("account", None)
        password = self.get_argument("password", None)

        if not account or not password:
            return self.finish({"code": "400", "msg": "参数不正确"})





