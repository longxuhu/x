---
comments: true
tags:
  - Python
  - 企业微信
---

# 企业微信消息加解密库（优化）

[加解密方案说明](https://developer.work.weixin.qq.com/document/path/90968)

[代码库下载](https://developer.work.weixin.qq.com/document/path/90307)

## 1. 准备

### 1.1. 依赖

```shell
pip install pycryptodome
```

??? question "如果出现 `ModuleNotFoundError: No module named 'Crypto'`"

    卸载掉 `Crypto`和`pycryoto` 包，然后重新安装 `pycryptodome` 即可。
    ```shell
    pip uninstall Crypto
    pip uninstall pycrypto

    pip uninstall pycryptodome
    pip install pycryptodome
    ```

### 1.2. <sup>*</sup>必要参数

```env
# 企业ID
CORP_ID = "wx****"
# Token
TOKEN = "***"
# EncodingAESKey
ENCODING_AES_Key = "***"
```

## 2. 代码

??? abstract "WXBizMsgCrypt3.py"

    ``` py
    import base64
    import hashlib
    import random
    import socket
    import struct
    import time
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
    
    
    class Crypt:
        """提供接收和推送给企业微信消息的加解密接口
        """
    
        def __init__(self, key):
            self.key = key  # self.key = base64.b64decode(key+"=")
            self.mode = AES.MODE_CBC  # 设置加解密模式为AES的CBC模式
    
        def encrypt(self, text: str, corp_id: str) -> str:
            """对明文进行加密
    
            :param text:        需要加密的明文
            :param corp_id:
            :return:            加密得到的字符串
            """
            # 16位随机字符串添加到明文开头
            # 使用自定义的填充方式对明文进行补位填充
            pkcs7 = PKCS7Encoder()
            text = pkcs7.encode(
                f'{str(random.randint(1000000000000000, 9999999999999999)).encode()}'
                f'{struct.pack("I", socket.htonl(len(text)))}'
                f'{text.encode()}'
                f'{corp_id.encode()}'
            )
            # 加密
            cryptor = AES.new(self.key, self.mode, self.key[:16])
            try:
                ciphertext = cryptor.encrypt(text)
                # 使用BASE64对加密后的字符串进行编码
                return base64.b64encode(ciphertext).decode('utf8')
            except (TypeError, ValueError):
                raise WXBizMsgCryptException('Encrypt AES Error.', WXBizMsgCrypt_EncryptAES_Error)
    
        def decrypt(self, text: str, corp_id: str) -> str:
            """对解密后的明文进行补位删除
    
            :param text:        密文
            :param corp_id:
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
    
            if from_receive_id.decode('utf8') != corp_id:
                raise WXBizMsgCryptException('Validate CorpId Error.', WXBizMsgCrypt_ValidateCorpId_Error)
            return xml_content
    
    
    class WXBizMsgCrypt:
    
        def __init__(self, token: str, encoding_aes_key: str, corp_id: str):
            """
            https://developer.work.weixin.qq.com/document/path/90238
            :param token:
            :param encoding_aes_key:
            :param corp_id:
            """
            try:
                self.key = base64.b64decode(encoding_aes_key + "=")
                assert len(self.key) == 32
            except ValueError:
                raise WXBizMsgCryptException('Illegal Aes Key.', WXBizMsgCrypt_IllegalAesKey)
            self.token = token
            self.corp_id = corp_id
    
        def verify_params(self, msg_signature: str, time_stamp: str, nonce: str, echo_str: str):
            """验证参数
            """
            try:
                if get_sha1(self.token, time_stamp, nonce, echo_str) != msg_signature:
                    raise WXBizMsgCryptException('Validate Signature Error.', WXBizMsgCrypt_ValidateSignature_Error)
            except TypeError:
                raise WXBizMsgCryptException('Compute Signature Error.', WXBizMsgCrypt_ComputeSignature_Error)
    
        def verify_url(self, msg_signature: str, time_stamp: str, nonce: str, echo_str: str):
            """验证URL
    
            :param msg_signature:   签名串，对应URL参数的msg_signature
            :param time_stamp:      时间戳，对应URL参数的timestamp
            :param nonce:           随机串，对应URL参数的nonce
            :param echo_str:        随机串，对应URL参数的echostr
            :return:                ret: 成功0，失败返回对应的错误码
                                    sReplyEchoStr: 解密之后的echo_str，当return返回0时有效
            """
            self.verify_params(msg_signature, time_stamp, nonce, echo_str)
            return Crypt(self.key).decrypt(echo_str, self.corp_id)
    
        def encrypt_msg(self, reply_msg: str, nonce: str, timestamp=None) -> str:
            """将企业回复用户的消息加密打包
    
            :param reply_msg:   企业号待回复用户的消息，xml格式的字符串
            :param nonce:       随机串，可以自己生成，也可以用URL参数的nonce
            :param timestamp:   时间戳，可以自己生成，也可以用URL参数的timestamp,如为None则自动用当前时间
            :return:            sEncryptMsg: 加密后的可以直接回复用户的密文，包括msg_signature, timestamp, nonce, encrypt的xml格式的字符串
                                ret: 成功0，sEncryptMsg,失败返回对应的错误码None
            """
            pc = Crypt(self.key)
            encrypt = pc.encrypt(reply_msg, self.corp_id)
            if timestamp is None:
                timestamp = str(int(time.time()))
            # 生成安全签名
            signature = get_sha1(self.token, timestamp, nonce, encrypt)
            return f"""
                <xml>
                <Encrypt><![CDATA[{encrypt}]]></Encrypt>
                <MsgSignature><![CDATA[{signature}]]></MsgSignature>
                <TimeStamp>{timestamp}</TimeStamp>
                <Nonce><![CDATA[{nonce}]]></Nonce>
                </xml>
            """
    
        def decrypt_msg(self, post_data: str, msg_signature: str, timestamp: str, nonce: str):
            """检验消息的真实性，并且获取解密后的明文
    
            :param post_data:       密文，对应POST请求的数据
            :param msg_signature:   签名串，对应URL参数的msg_signature
            :param timestamp:       时间戳，对应URL参数的timestamp
            :param nonce:           随机串，对应URL参数的nonce
            :return:                成功0，失败返回对应的错误码
                                    xml_content: 解密后的原文，当return返回0时有效
            """
            try:
                xml_tree = cElementTree.fromstring(post_data)
                encrypt = xml_tree.find("Encrypt").text
                self.verify_params(msg_signature, timestamp, nonce, encrypt)
                return Crypt(self.key).decrypt(encrypt, self.corp_id)
            except cElementTree.ParseError:
                raise WXBizMsgCryptException("XML Parse Error.", WXBizMsgCrypt_ParseXml_Error)
    
    ```

## 3. 使用

### 3.1. 实例化

```python
from WXBizMsgCrypt3 import WXBizMsgCrypt

# 准备参数
token = ''
encoding_aes_key = ''
corp_id = ''

# 实例化
wecom_crypt = WXBizMsgCrypt(token, encoding_aes_key, corp_id)
```

### 3.2. 验证参数有效性

```python
# 参数
msg_signature = ''
timestamp = ''
nonce = ''
echo_str = ''

# 验证URL
valid: bool = wecom_crypt.verify_params(msg_signature, timestamp, nonce, echo_str)
```

### 3.3. 接收消息服务器配置

#### 3.3.1. 验证服务器

=== ":simple-fastapi: FastAPI"

    ```python
    @router.get('/callback/', name='企业微信回调验证URL有效性')
    async def callback(
            msg_signature: str = Query(title='企业微信加密签名'),
            timestamp: str = Query(title='时间戳'),
            nonce: str = Query(title='随机数'),
            echo_str: str = Query(title='加密的字符串'),
    ) -> Response:
        """验证URL有效性
        """
        try:
            wecom_crypt = WXBizMsgCrypt(token, encoding_aes_key, corp_id)
            return Response(wecom_crypt.verify_url(msg_signature, timestamp, nonce, echo_str))
        except WXBizMsgCryptException as e:
            return Response(e.message, status_code=422)
    
    ```

#### 3.3.2. 接收消息

=== ":simple-fastapi: FastAPI"

    ```python
    @router.post('/callback/', name='企业微信回调接收消息')
    async def callback(
            request: Request,
            msg_signature: str = Query(title='企业微信加密签名'),
            timestamp: str = Query(title='时间戳'),
            nonce: str = Query(title='随机数'),
    ) -> Response:
        ) -> Response:
    
    
    try:
        wecom_crypt = WXBizMsgCrypt(token, encoding_aes_key, corp_id)
        msg = wecom_crypt.decrypt_msg((await request.body()).decode('utf-8'), msg_signature, timestamp, nonce)
        msg_dict = dict(xmltodict.parse(msg).get('xml'))
        # 处理消息...
    except WXBizMsgCryptException as e:
        return Response(e.message, status_code=422)
    
    ```

---
