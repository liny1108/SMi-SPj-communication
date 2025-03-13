import hmac
import hashlib

# HKDF 生成32字节密钥  字节类型
def derive_key_hkdf(shared_key: bytes, info: str, length: int = 32):
    salt = b""  
    prk = hmac.new(salt, shared_key, hashlib.sha256).digest()  # HKDF 提取步骤
    okm = hmac.new(prk, info.encode(), hashlib.sha256).digest()[:length]  # HKDF 扩展步骤
    return okm

# HKDF
def HKDF_keys(SK , W):
    if W == 'SP':
        kr = derive_key_hkdf(SK, "send")
        ks = derive_key_hkdf(SK, "receive")
    elif W == 'SM':
        ks = derive_key_hkdf(SK, "send")
        kr = derive_key_hkdf(SK, "receive")
    return ks, kr

# HMAC   32字节
def derive_key_hmac(SK: bytes, info: str, length: int = 32):
    return hmac.new(SK, info.encode(), hashlib.sha256).digest()[:length]
# HMAC
def HMAC_keys(SK, W):
    if W == 'SP':
        kr = derive_key_hkdf(SK, "send")
        ks = derive_key_hkdf(SK, "receive")
    elif W == 'SM':
        ks = derive_key_hkdf(SK, "send")
        kr = derive_key_hkdf(SK, "receive")
    return ks, kr

# KDF1   32字节
def derive_key_kdf1(SK: bytes, info: str, length: int = 32):
    return hashlib.sha256(SK + info.encode()).digest()[:length]
# KDF
def KDF_keys(SK, W):
    if W == 'SP':
        kr = derive_key_hkdf(SK, "send")
        ks = derive_key_hkdf(SK, "receive")
    elif W == 'SM':
        ks = derive_key_hkdf(SK, "send")
        kr = derive_key_hkdf(SK, "receive")
    return ks, kr

# def derive_key(sock, IDj, s, SPj_ip):
#     # 假设 SKsm 是从认证流程中得到的
#     SK, sk_time, SMi_ip =  spj_sksp.run_authentication(sock, IDj, s, SPj_ip)
#     # 生成发送密钥和接收密钥
#     ks, kr = HMAC_keys(SK)
    
#     print(f"发送密钥 ks: {ks.hex()}")
#     print(f"接收密钥 kr: {kr.hex()}")
#     return SK, ks, kr, SMi_ip

    


