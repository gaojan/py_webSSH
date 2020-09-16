import ipaddress
import rsa
import re
import time
import os
import hmac
import base64
from hashlib import md5, sha1, sha256
from app.settings import KEY


try:
    from types import UnicodeType
except ImportError:
    UnicodeType = str

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


numeric = re.compile(r'[0-9]+$')
allowed = re.compile(r'(?!-)[a-z0-9-]{1,63}(?<!-)$', re.IGNORECASE)


def to_str(bstr, encoding='utf-8'):
    if isinstance(bstr, bytes):
        return bstr.decode(encoding)
    return bstr


def to_bytes(ustr, encoding='utf-8'):
    if isinstance(ustr, UnicodeType):
        return ustr.encode(encoding)
    return ustr


def to_int(string):
    try:
        return int(string)
    except (TypeError, ValueError):
        pass


def to_ip_address(ipstr):
    return ipaddress.ip_address(to_str(ipstr))


def is_valid_ip_address(ipstr):
    try:
        to_ip_address(ipstr)
    except ValueError:
        return False
    return True


def is_valid_port(port):
    return 0 < port < 65536


def is_ip_hostname(hostname):
    it = iter(hostname)
    if next(it) == '[':
        return True
    for ch in it:
        if ch != '.' and not ch.isdigit():
            return False
    return True


def is_valid_hostname(hostname):
    if hostname[-1] == '.':
        # strip exactly one dot from the right, if present
        hostname = hostname[:-1]
    if len(hostname) > 253:
        return False

    labels = hostname.split('.')

    # the TLD must be not all-numeric
    if numeric.match(labels[-1]):
        return False

    return all(allowed.match(label) for label in labels)


def is_same_primary_domain(domain1, domain2):
    i = -1
    dots = 0
    l1 = len(domain1)
    l2 = len(domain2)
    m = min(l1, l2)

    while i >= -m:
        c1 = domain1[i]
        c2 = domain2[i]

        if c1 == c2:
            if c1 == '.':
                dots += 1
                if dots == 2:
                    return True
        else:
            return False

        i -= 1

    if l1 == l2:
        return True

    if dots == 0:
        return False

    c = domain1[i] if l1 > m else domain2[i]
    return c == '.'


def parse_origin_from_url(url):
    url = url.strip()
    if not url:
        return

    if not (url.startswith('http://') or url.startswith('https://') or
            url.startswith('//')):
        url = '//' + url

    parsed = urlparse(url)
    port = parsed.port
    scheme = parsed.scheme

    if scheme == '':
        scheme = 'https' if port == 443 else 'http'

    if port == 443 and scheme == 'https':
        netloc = parsed.netloc.replace(':443', '')
    elif port == 80 and scheme == 'http':
        netloc = parsed.netloc.replace(':80', '')
    else:
        netloc = parsed.netloc

    return '{}://{}'.format(scheme, netloc)


def get_time_stamp(dt):
    """ 秒级时间戳 """
    return int(dt.timestamp())


def create_uuid_str():
    """生成随机字符串"""
    return md5((str(os.urandom(24)) + str(int(time.time()))).encode('utf-8')).hexdigest()


def create_md5_str(string):
    """生成md5加密字符串"""
    return md5(string.encode('utf-8')).hexdigest()


def create_sha_str(string):
    psw = sha1()
    psw.update(string.encode('utf8'))
    return psw.hexdigest()


def get_current_time():
    """获取当前时间"""
    return time.strftime("%Y-%m-%d %H:%S:%M")


def read_file(input_file):
    with open(input_file, 'rb') as f:
        message = f.read()
    return message


def encrypt(msg, pub_key):
    """
    公钥加密
    :param msg:
    :param pub_key:
    :return:
    """
    pubkey = rsa.PublicKey.load_pkcs1(pub_key)
    original_text = msg.encode('utf8')
    crypt_text = rsa.encrypt(original_text, pubkey)
    crypt_str = bytes.decode(base64.b64encode(crypt_text))
    return crypt_str  # 加密后的密文


def decrypt(cipher_text, pri_key):
    """
    私钥解密
    :param cipher_text:
    :param pri_key:
    :return: str
    """
    cipher_text = base64.b64decode(cipher_text)
    privatekey = rsa.PrivateKey.load_pkcs1(pri_key)
    lase_text = rsa.decrypt(cipher_text, privatekey).decode()
    return lase_text


# pri = read_file("./key/private.pem")
# pub = read_file("./key/public.pem")
# msg = "hahahaha"
#
# cipher = encrypt(msg, pub)
# print("加密后>>>", cipher)
# text = decrypt(cipher, pri)
# print("解密后>>>", text)

