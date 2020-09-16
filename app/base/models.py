#!usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from sqlalchemy.ext.declarative import DeclarativeMeta
from sqlalchemy import Column
from app.database import Base
from sqlalchemy.orm import sessionmaker
from app.database import engine
from sqlalchemy.orm.state import InstanceState


class DBSessionContext(object):
    """session"""
    def __init__(self):
        self.db_engine = engine

    def __enter__(self):
        """当with开始运行的时候触发此方法的运行, 必须有返回"""
        self.session = sessionmaker(bind=self.db_engine)()
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        """当with运行结束之后触发此方法的运行"""
        self.session.close()


class ModelMetaClass(DeclarativeMeta):
    """读取表模型所有字段"""
    def __new__(cls, name, bases, attrs):
        attrs['model_fields'] = []
        for base in bases:
            if hasattr(base, 'model_fields'):
                attrs['model_fields'] = attrs['model_fields'] + getattr(base, 'model_fields')
        for key, value in attrs.items():
            if isinstance(value, Column) and key not in attrs['model_fields']:
                attrs['model_fields'].append(key)
        return type.__new__(cls, name, bases, attrs)


class BaseModel(Base, metaclass=ModelMetaClass):
    """字段序列化json"""
    __abstract__ = True

    @staticmethod
    def change_value(value):
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d_%H:%M:%S")
        return value

    def to_json(self, fields=None):
        if not fields:
            fields = self.__dict__.keys()
        # 去掉InstanceState，因为不能序列化
        return {key: self.change_value(value) for key, value in self.__dict__.items() if
                key in fields and not isinstance(value, InstanceState)}

