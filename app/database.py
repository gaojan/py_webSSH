import redis as _redis
from app.settings import REDIS
from datetime import datetime,  timedelta
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from app.utils import get_time_stamp
from app.settings import (MYSQL, TOKEN_USER_KEY, TOKEN_CONNECTOR,
                          TOKEN_EXPIRATION, USER_TOKEN_KEY)


# mysql
mysql_config = 'mysql+pymysql://{user}:{password}@{ip}:{port}/{database}?charset=utf8'.format(**MYSQL)
engine = create_engine(mysql_config, convert_unicode=True, encoding='utf-8', echo=False)
Base = declarative_base()

redis_client = _redis.StrictRedis(**REDIS)


def get_token_info(token):
    """ 获取Redis的token里的信息 """
    token_info = redis_client.hget(TOKEN_USER_KEY, token)
    if not token_info:
        return None, None
    user_id, expiration = token_info.decode().split(TOKEN_CONNECTOR)
    return int(user_id), datetime.fromtimestamp(int(expiration))


def refresh_token(user_id):
    """ 刷新token的过期时间 """
    token, session_key = get_redis_user(user_id)  # 根据user_id从Redis里获取token
    new_expiration_int = get_time_stamp(datetime.now() + timedelta(seconds=TOKEN_EXPIRATION))
    token_info = str(user_id) + TOKEN_CONNECTOR + str(new_expiration_int)
    redis_client.hset(TOKEN_USER_KEY, token, token_info)  # 设置新的token信息


def delete_token(user_id):
    """ 删除token """
    token, session_key = get_redis_user(user_id)
    redis_client.hdel(TOKEN_USER_KEY, token)
    redis_client.hdel(USER_TOKEN_KEY, user_id)


def get_redis_user(user_id):
    """ 获取Redis的user里的信息 """
    user_info = redis_client.hget(USER_TOKEN_KEY, user_id)
    if not user_info:
        return None, None
    return user_info.decode().split(TOKEN_CONNECTOR)

