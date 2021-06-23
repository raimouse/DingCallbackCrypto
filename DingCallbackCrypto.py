# coding=utf-8
#pip install pycryptodome
import time
#加解密相关包
import json
import uuid
import struct
import base64
import hashlib
import binascii
import string
import io
import logging
from random import choice
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

#回调加解密参数
encode_key = 'FqBCgHeA3BEcW3HLW1RdEcQQxlvhrCTWuDXz5lcZ77m'
aes_token = 'CeoYLc8tnHYkO7aulRF6sPv'

#base64解码得出用于加解密的aes_key
aes_key = base64.b64decode(encode_key+'=')

class DingCallbackCrypto:
    def __init__(self,aes_key,app_key,aes_token):
        self.aes_key = aes_key
        self.app_key = app_key
        self.aes_token = aes_token

    #生成响应数据
    def getEncryptedMap(self,plaintext):
        encrypt = self.encrypt(plaintext)
        timestamp = str(int(time.time()))
        nonce = self.generateRandomKey(16)
        sign = self.generateSignature(nonce, timestamp, self.aes_token,encrypt)
        #钉钉响应参数中的timeStamp是大写S,但http推送中是timestamp
        return {'msg_signature':sign,
                'timeStamp':timestamp,
                'nonce':nonce,
                'encrypt':encrypt}

    ##解密钉钉发送的数据
    def getDecryptMsg(self,msg_signature,timestamp,nonce,encrypt):
        #计算消息签名是否正确
        sign = self.generateSignature(nonce, timestamp, self.aes_token,encrypt)
        #print(sign, msg_signature)
        if msg_signature != sign:
            raise ValueError('signature check error')
        #首先对密文进行base64解码             
        content = base64.decodebytes(encrypt.encode('UTF-8'))  
        #初始向量为aes_key取前16位
        iv = self.aes_key[:16]
        #进行aes解密提取明文
        aesDecode = AES.new(self.aes_key, AES.MODE_CBC, iv)
        decodeRes = aesDecode.decrypt(content)
        #计算填充字节数
        padtext = decodeRes[-1]
        if padtext > 32:
            raise ValueError('Input is not padded or padding is corrupt')
        #去除填充字节
        decodeRes = decodeRes[:-padtext]
        #获取明文字符串长度
        length = struct.unpack('!i', decodeRes[16:20])[0]
        #校验尾部是否为对应的app_key
        if decodeRes[(20+length):].decode() != self.app_key:
            raise ValueError('app_key 校验错误')
        #提取明文消息体
        return decodeRes[20:(20+length)].decode()
    
    #加密明文
    def encrypt(self,encrypt):
        msg_len = self.getlength(encrypt)
        #拼接明文
        msg = ''.join([self.generateRandomKey(16) , msg_len.decode() , encrypt , self.app_key])
        #填充为16字节的倍数
        pad_msg = pad(msg.encode('utf-8'),AES.block_size)
        #pad_msg = self.pks7encode(msg)
        #初始向量iv为aes_key前16位
        iv = self.aes_key[:16]
        aesEncode = AES.new(self.aes_key, AES.MODE_CBC, iv)
        aesEncrypt = aesEncode.encrypt(pad_msg)
        #print(len(base64.encodebytes(aesEncrypt).decode('UTF-8')))
        #print(base64.encodebytes(aesEncrypt))
        #密文需要再进行一次base64加密
        return base64.encodebytes(aesEncrypt).decode('UTF-8')

    # 生成回调返回使用的签名值
    def generateSignature(self, nonce, timestamp, aes_token, encrypt):
        signList = ''.join(sorted([nonce, timestamp, aes_token, encrypt]))
        return hashlib.sha1(signList.encode()).hexdigest()

    #获取密文长度并转换为4字节编码
    def getlength(self, encrypt):
        length = len(encrypt)
        return struct.pack('>l', length)
    
    #生成加密所需要的随机字符串
    def generateRandomKey(self, size, chars=string.ascii_letters + string.ascii_lowercase + string.ascii_uppercase + string.digits):
        return ''.join(choice(chars) for i in range(size))


if __name__=='__main__':
    
    msg_signature = "d1747072b86aebcee22597761dcdac6a3a980b05"
    encrypt = "0LShNpSY+NPpfEmoCnfvh68cGacA1aX5hQIZdPI7iLDBYV1YzbzqdfUdLm7X4vhT"
    timestamp = "1624371594"
    nonce = "zkHZNsSTNK3KupkY"
    dingCrypto = DingCallbackCrypto(aes_key,app_key,aes_token) 
    msg = dingCrypto.getDecryptMsg(msg_signature,timestamp,nonce,encrypt)
    print(msg)
