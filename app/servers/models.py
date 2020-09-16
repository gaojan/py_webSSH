from app.base.models import BaseModel
from app.utils import get_current_time
from app.base.models import DBSessionContext
from sqlalchemy import Column, String, Integer, DateTime, SmallInteger


class Servers(BaseModel):

    __tablename__ = "t_servers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(45))
    host = Column(String(45))
    port = Column(Integer)
    username = Column(String(45))
    password = Column(String(200))
    create_user_id = Column(Integer)
    create_dt = Column(DateTime, nullable=get_current_time())
    update_dt = Column(DateTime, nullable=get_current_time())
    status = Column(SmallInteger)


class ServersViewModel(object):

    @classmethod
    def add_server(cls, server):
        with DBSessionContext() as db_session:
            db_session.add(server)
            db_session.flush()
            db_session.commit()

    @classmethod
    def get_servers_list(cls):
        with DBSessionContext() as db_session:
            host_list = db_session.query(Servers).filter(Servers.status == 1).all()
            return host_list

    @classmethod
    def get_server_by_name(cls, name):
        with DBSessionContext() as db_session:
            server = db_session.query(Servers).filter(Servers.name == name, Servers.status == 1).first()
            return server

    @classmethod
    def get_server_by_id(cls, host_id):
        with DBSessionContext() as db_session:
            server = db_session.query(Servers).filter(Servers.id == host_id, Servers.status == 1).first()
            return server
