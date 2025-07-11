import time
import hmac
import hashlib
import base64

import requests

from config import config
def get_flag(url):
    ak = config.get("accessKey")
    sk = config.get("secretKey")
    timestamp = str(time.time_ns())
    sign = compute_signature(timestamp,sk)
    headers ={
        "X-Access-Key":ak,
        "X-Signature":sign,
        "X-Timestamp":timestamp,

    }
    rp = requests.get(url,headers=headers,verify=False)
    return rp.text
def compute_signature(data: str, secret_key: str) -> str:
    """
    计算 HMAC-SHA256 签名

    参数:
        data: 要签名的数据字符串
        secret_key: 用于签名的密钥

    返回:
        Base64 编码的签名字符串
    """
    # 将密钥和数据转换为字节
    key_bytes = secret_key.encode('utf-8')
    data_bytes = data.encode('utf-8')

    # 创建 HMAC-SHA256 签名
    signature = hmac.new(key_bytes, data_bytes, hashlib.sha256).digest()

    # 返回 Base64 编码的签名
    return base64.b64encode(signature).decode('utf-8')
