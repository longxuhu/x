---
comments: true
tags:
  - Python
draft:
  - true
---

# 企业微信消息加解密库（优化后）

> [官方说明](https://developer.work.weixin.qq.com/document/path/90307#python%E5%BA%93)

``` py title="WXBizMsgCrypt3.py" linenums="1"
import base64
import hashlib
import random
import socket
import struct
import time
from typing import Optional
from xml.etree import cElementTree

from Crypto.Cipher import AES

WXBizMsgCrypt_OK = 0
WXBizMsgCrypt_ValidateSignature_Error = -40001
WXBizMsgCrypt_ParseXml_Error = -40002
WXBizMsgCrypt_ComputeSignature_Error = -40003
WXBizMsgCrypt_IllegalAesKey = -40004
WXBizMsgCrypt_ValidateCorpId_Error = -40005
WXBizMsgCrypt_EncryptAES_Error = -40006
WXBizMsgCrypt_DecryptAES_Error = -40007
WXBizMsgCrypt_IllegalBuffer = -40008
WXBizMsgCrypt_EncodeBase64_Error = -40009
WXBizMsgCrypt_DecodeBase64_Error = -40010
WXBizMsgCrypt_GenReturnXml_Error = -40011


class WXBizMsgCryptException(Exception):

    def __init__(self, message: str, code: int):
        self.message = message
        self.code = code

    def __str__(self):
        return f"[WXBizMsgCryptException] {self.message} ({self.code})"


def get_sha1(token: str, timestamp: str, nonce: str, encrypt: str) -> str:
    """用SHA1算法生成安全签名

    :param token:       票据
    :param timestamp:   时间戳
    :param nonce:       密文
    :param encrypt:     随机字符串
    :return:            安全签名
    """
    try:
        sort_list = [token, timestamp, nonce, encrypt]
        sort_list.sort()
        sha = hashlib.sha1()
        sha.update("".join(sort_list).encode())
        return sha.hexdigest()
    except TypeError:
        raise WXBizMsgCryptException("Compute Signature Error.", WXBizMsgCrypt_ComputeSignature_Error)


def xml_extract(xml_text: str) -> Optional[str]:
    """提取出xml数据包中的加密消息
    """
    try:
        xml_tree = cElementTree.fromstring(xml_text)
        encrypt = xml_tree.find("Encrypt")
        return encrypt.text
    except cElementTree.ParseError:
        raise WXBizMsgCryptException("XML Parse Error.", WXBizMsgCrypt_ParseXml_Error)


def xml_generate(encrypt: str, signature: str, timestamp: str, nonce: str) -> str:
    """生成xml消息
    """
    return f"""
        <xml>
        <Encrypt><![CDATA[{encrypt}]]></Encrypt>
        <MsgSignature><![CDATA[{signature}]]></MsgSignature>
        <TimeStamp>{timestamp}</TimeStamp>
        <Nonce><![CDATA[{nonce}]]></Nonce>
        </xml>
    """


class PKCS7Encoder:
    """提供基于PKCS7算法的加解密接口
    """

    block_size = 32

    def encode(self, text):
        """对需要加密的明文进行填充补位

        :param text:    需要进行填充补位操作的明文
        :return:        补齐明文字符串
        """
        text_length = len(text)
        # 计算需要填充的位数
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        # 获得补位所用的字符
        pad = chr(amount_to_pad)
        return text + (pad * amount_to_pad).encode()

    def decode(self, decrypted):
        """删除解密后明文的补位字符

        :param decrypted:   解密后的明文
        :return:            删除补位字符后的明文
        """
        pad = ord(decrypted[-1])
        if pad < 1 or pad > self.block_size:
            pad = 0
        return decrypted[:-pad]


def get_random_str() -> bytes:
    """ 随机生成16位字符串
    @return: 16位字符串
    """
    return str(random.randint(1000000000000000, 9999999999999999)).encode()


class Crypt:
    """提供接收和推送给企业微信消息的加解密接口
    """

    def __init__(self, key):
        self.key = key  # self.key = base64.b64decode(key+"=")
        self.mode = AES.MODE_CBC  # 设置加解密模式为AES的CBC模式

    def encrypt(self, text: str, receive_id: str):
        """对明文进行加密

        :param text:        需要加密的明文
        :param receive_id:
        :return:            加密得到的字符串
        """
        # 16位随机字符串添加到明文开头
        # 使用自定义的填充方式对明文进行补位填充
        pkcs7 = PKCS7Encoder()
        text = pkcs7.encode(
            f'{get_random_str()}'
            f'{struct.pack("I", socket.htonl(len(text)))}'
            f'{text.encode()}'
            f'{receive_id.encode()}'
        )
        # 加密
        cryptor = AES.new(self.key, self.mode, self.key[:16])
        try:
            ciphertext = cryptor.encrypt(text)
            # 使用BASE64对加密后的字符串进行编码
            base64.b64encode(ciphertext).decode('utf8')
        except (TypeError, ValueError):
            raise WXBizMsgCryptException('Encrypt AES Error.', WXBizMsgCrypt_EncryptAES_Error)

    def decrypt(self, text, receive_id):
        """对解密后的明文进行补位删除

        :param text:        密文
        :param receive_id:
        :return:            删除填充补位后的明文
        """
        try:
            cryptor = AES.new(self.key, self.mode, self.key[:16])
            # 使用BASE64对密文进行解码，然后AES-CBC解密
            plain_text = cryptor.decrypt(base64.b64decode(text))
        except (ValueError, TypeError):
            raise WXBizMsgCryptException('Decrypt AES Error.', WXBizMsgCrypt_DecryptAES_Error)
        try:
            pad = plain_text[-1]
            # 去掉补位字符串
            # pkcs7 = PKCS7Encoder()
            # plain_text = pkcs7.encode(plain_text)
            # 去除16位随机字符串
            content = plain_text[16:-pad]
            xml_len = socket.ntohl(struct.unpack("I", content[: 4])[0])
            xml_content = content[4: xml_len + 4]
            from_receive_id = content[xml_len + 4:]
        except (ValueError, TypeError, struct.error):
            raise WXBizMsgCryptException('Illegal Buffer.', WXBizMsgCrypt_IllegalBuffer)

        if from_receive_id.decode('utf8') != receive_id:
            raise WXBizMsgCryptException('Validate CorpId Error.', WXBizMsgCrypt_ValidateCorpId_Error)
        return xml_content


class WXBizMsgCrypt(object):

    def __init__(self, s_token: str, s_encoding_aes_key: str, s_receive_id: str):
        try:
            self.key = base64.b64decode(s_encoding_aes_key + "=")
            assert len(self.key) == 32
        except ValueError:
            raise WXBizMsgCryptException('Illegal Aes Key.', WXBizMsgCrypt_IllegalAesKey)
        self.m_sToken = s_token
        self.m_sReceiveId = s_receive_id

    def verify_params(self, s_msg_signature: str, s_time_stamp: str, s_nonce: str, s_echo_str: str):
        """验证参数
        """
        try:
            if get_sha1(self.m_sToken, s_time_stamp, s_nonce, s_echo_str) != s_msg_signature:
                raise WXBizMsgCryptException('Validate Signature Error.', WXBizMsgCrypt_ValidateSignature_Error)
        except TypeError:
            raise WXBizMsgCryptException('Compute Signature Error.', WXBizMsgCrypt_ComputeSignature_Error)

    def verify_url(self, s_msg_signature: str, s_time_stamp: str, s_nonce: str, s_echo_str: str):
        """验证URL

        :param s_msg_signature:     签名串，对应URL参数的msg_signature
        :param s_time_stamp:        时间戳，对应URL参数的timestamp
        :param s_nonce:             随机串，对应URL参数的nonce
        :param s_echo_str:          随机串，对应URL参数的echostr
        :return:                    ret: 成功0，失败返回对应的错误码
                                    sReplyEchoStr: 解密之后的echostr，当return返回0时有效
        """
        self.verify_params(s_msg_signature, s_time_stamp, s_nonce, s_echo_str)
        return Crypt(self.key).decrypt(s_echo_str, self.m_sReceiveId)

    def encrypt_msg(self, s_reply_msg: str, s_nonce: str, timestamp=None) -> str:
        """将企业回复用户的消息加密打包

        :param s_reply_msg:         企业号待回复用户的消息，xml格式的字符串
        :param s_nonce:             随机串，可以自己生成，也可以用URL参数的nonce
        :param timestamp:           时间戳，可以自己生成，也可以用URL参数的timestamp,如为None则自动用当前时间
        :return:                    sEncryptMsg: 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
                                    ret: 成功0，sEncryptMsg,失败返回对应的错误码None
        """
        pc = Crypt(self.key)
        encrypt = pc.encrypt(s_reply_msg, self.m_sReceiveId)
        if timestamp is None:
            timestamp = str(int(time.time()))
        # 生成安全签名
        signature = get_sha1(self.m_sToken, timestamp, s_nonce, encrypt)
        return xml_generate(encrypt, signature, timestamp, s_nonce)

    def decrypt_msg(self, s_post_data, s_msg_signature, s_time_stamp, s_nonce):
        """检验消息的真实性，并且获取解密后的明文

        :param s_post_data:         密文，对应POST请求的数据
        :param s_msg_signature:     签名串，对应URL参数的msg_signature
        :param s_time_stamp:        时间戳，对应URL参数的timestamp
        :param s_nonce:             随机串，对应URL参数的nonce
        :return:                    ret: 成功0，失败返回对应的错误码
                                    xml_content: 解密后的原文，当return返回0时有效
        """
        # 验证安全签名
        encrypt = xml_extract(s_post_data)
        self.verify_params(s_msg_signature, s_time_stamp, s_nonce, encrypt)
        return Crypt(self.key).decrypt(encrypt, self.m_sReceiveId)

```
