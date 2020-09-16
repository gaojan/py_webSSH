import rsa
from Crypto import Random
from Crypto.PublicKey import RSA
from binascii import b2a_hex, a2b_hex

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
import base64
import sys



class RsaCrypt:
    def __init__(self, pubkey, prikey):
        self.pubkey = pubkey
        self.prikey = prikey

    def encrypt(self, text):
        self.ciphertext = rsa.encrypt(text.encode(), self.pubkey)
        # 因为rsa加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        return b2a_hex(self.ciphertext)

    def decrypt(self, text):
        decrypt_text = rsa.decrypt(a2b_hex(text), prikey)
        return decrypt_text


def read_file(input_file):
    with open(input_file, 'rb') as f:
        message = f.read()
    return message


def encrypt_file(message, pubkey_file):
    with open(pubkey_file, 'r') as f:
        public_key = f.read()
    pub_key_obj = RSA.importKey(public_key)
    cipher_obj = Cipher_PKCS1_v1_5.new(pub_key_obj)
    cipher_text = base64.b64encode(cipher_obj.encrypt(message))
    # res = []
    # for i in range(0, len(message), 200):
    #     res.append(base64.b64encode(cipher_obj.encrypt(message[i:i + 200])))
    # cipher_text = b"".join(res)
    return cipher_text
    # with open(out_file, 'wb') as f_w:
    #     f_w.write(cipherText)
    # pass


def encrypt_rsa(sign_content, private_key):
    sign_content = sign_content.encode('utf-8')
    signature = rsa.sign(sign_content, rsa.PrivateKey.load_pkcs1(private_key, format='PEM'), 'SHA-256')
    sign = base64.b64encode(signature)
    return str(sign, encoding='utf-8')


# def decrypt_rsa(ciphertext, public_key):


def create_keys():  # 生成公钥和私钥
    (pubkey, privkey) = rsa.newkeys(1024)
    pub = pubkey.save_pkcs1()
    with open('public.pem', 'wb+')as f:
        f.write(pub)

    pri = privkey.save_pkcs1()
    with open('private.pem', 'wb+')as f:
        f.write(pri)


def encrypt(msg, pub_key):  # 用公钥加密
    # with open('public.pem', 'rb') as f:
    #     p = f.read()
    pubkey = rsa.PublicKey.load_pkcs1(pub_key)
    original_text = msg.encode('utf8')
    crypt_text = rsa.encrypt(original_text, pubkey)
    print(bytes.decode(base64.b64encode(crypt_text)))
    print(type(bytes.decode(base64.b64encode(crypt_text))))
    return crypt_text  # 加密后的密文
    # f = open('passwd.data', 'wb')
    # f.write(crypt_text)
    # f.close()


def decrypt(ciphertext, pri_key):  # 用私钥解密
    # with open('private.pem', 'rb') as f:
    #     p = f.read()
    privkey = rsa.PrivateKey.load_pkcs1(pri_key)
    # f = open('passwd.data', 'rb')
    # crypt_text = f.read()
    lase_text = rsa.decrypt(ciphertext, privkey).decode()  # 注意，这里如果结果是bytes类型，就需要进行decode()转化为str

    print(lase_text)
    return lase_text


if __name__ == '__main__':

    # create_keys()
    pri_key = read_file("./key/private.pem")
    pub_key = read_file("./key/public.pem")
    msg = "gaojiangaojian"

    a = encrypt(msg, pub_key)
    print("加密后>>", a)
    b = decrypt(a, pri_key)
    print("解密后>>>", b)


    # rs_obj = RsaCrypt(pubkey, prikey)
    # text = 'hello'
    # ency_text = rs_obj.encrypt(text)
    # print(ency_text)
    # print(rs_obj.decrypt(ency_text))

    # # 获取一个伪随机数生成器
    # random_generator = Random.new().read
    # # 获取一个rsa算法对应的密钥对生成器实例
    # rsa = RSA.generate(2048, random_generator)
    #
    # # 生成私钥并保存
    # private_pem = rsa.exportKey()
    # with open('prikey.pem', 'wb') as f:
    #     f.write(private_pem)
    #
    # public_pem = rsa.publickey().exportKey()
    # with open('pubkey.pem', 'wb') as f:
    #     f.write(public_pem)

