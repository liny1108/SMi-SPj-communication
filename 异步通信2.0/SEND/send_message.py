import hmac
import hashlib
import time
import json
import socket
import os
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

def log_message(message):
    """ 将消息写入日志文件 """
    with open("send_message_log.txt", "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

def timing_decorator(func):
    """ 装饰器用于计算函数执行时间 """
    def wrapper(*args, **kwargs):
        #start_time = time.perf_counter_ns()  # 纳秒
        start_time = time.time() * 1000      # 毫秒
        result = func(*args, **kwargs)
        #end_time = time.perf_counter_ns()    # 纳秒
        end_time = time.time() * 1000      # 毫秒
        elapsed_time = end_time - start_time
        operation_times[func.__name__] += elapsed_time
        return result
    return wrapper

# 记录各个操作的时间
operation_times = {
    "compute_hash": 0,       # 哈希
    #"decrypt_data": 0,      # 解密
    "encrypt_message": 0,    # 加密
    "hmac_kdf": 0,           # HMAC计算
    "total_time": 0          # 总时间
}

# HMAC 32字节
@timing_decorator
def hmac_kdf(SK: bytes, data: bytes, length: int = 32):
    return hmac.new(SK, data, hashlib.sha256).digest()[:length]

# 生成时间戳的函数 int 类型
def generate_timestamp():
    return int(time.time())  

# 计算哈希值  字节类型 
@timing_decorator
def compute_hash(data: bytes):
    return hashlib.sha256(data).digest() 

# 加密   base64编码字节类型
@timing_decorator
def encrypt_message(key, data):
    # 如果密钥是字符串类型，则先编码为字节类型
    if isinstance(key, str):
        key = key.encode('utf-8')
    n = b'123456789012'  # 固定值 12字节
    #n = os.urandom(12)  # 随机生成
    data = data.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CTR, nonce=n)       # AES加密  CTR模式 nonce固定
    enc_data = cipher.encrypt(data)                    # 加密
    return base64.b64encode(enc_data)
    #return base64.b64encode(cipher.nonce + enc_data)   # 包含 Nonce 以便解密时使用

# 发送消息 发{i; Ci; Tag; ti }
def send_message(sock, port,  rev_ip, Ci: bytes, Tag: bytes, ti: int, message_id: int):
    message = {'j':message_id ,'Ci': Ci.decode('utf-8'), 'Tag': Tag.hex(), 'ti': ti}
    message_json = json.dumps(message)
    #print(f"发送消息: {message_json}")
    log_message(f"发送消息: {message_json}")
    sock.sendto(message_json.encode('utf-8'), (rev_ip, port))  # 发送到服务提供商

# 计算需要发送的消息,调用send_message 发送消息
def send_data(sock, port, rev_ip, ks: bytes, k: bytes, SK: bytes, message: str, message_id: int):
    
    Ci = encrypt_message(ks, message)   # 加密消息     Ci 字节类型
    # print(f"发送密钥：{ks.hex()}")
    ti = generate_timestamp()           # 生成时间戳   int 类型
    tag_data = Ci + ti.to_bytes(4, 'big')  
    Tag = hmac_kdf(SK, tag_data)        # 生成消息标签 Tag 字节类型
     
    send_message(sock, port, rev_ip, Ci, Tag, ti, message_id) # 发送消息 
    # print(f"首次发送消息")
    
    ks_new = hmac_kdf(ks, k)            # 更新发送密钥 ks' = HMAC(ks, k)
    k_new = compute_hash(ks_new + k)    # 更新辅助密钥 k' = H(ks' || k)
    return Ci, ks_new, k_new

# 重传消息的函数   {i; Ci；Tag’； ti’}
def retransmit_message(sock, port, rev_ip, SK: bytes, Ci: bytes, message_id: int):
    
    ti_new = generate_timestamp()                   # 重新生成新的时间戳 ti'
    tag_data_new = Ci + ti_new.to_bytes(4, 'big')   # (Ci || ti')
    Tag_new = hmac_kdf(SK, tag_data_new)            # 计算新的消息标签 Tag' = HMAC(SK, (Ci || ti’))

    # 重新发送消息
    send_message(sock, port, rev_ip, Ci, Tag_new, ti_new, message_id)
    #print(f"重新发送消息：{message_id}")
    log_message(f"重新发送消息：{message_id}")

    #return ti_new, Tag_new  # 返回新的时间戳和消息标签

# 密钥重置函数
def reset_keys(sock, port, rev_ip, SK: bytes):
    
    x = os.urandom(32)                      # 生成32字节的高熵随机数
    ks_reset = hmac_kdf(SK, x)              # 新的发送密钥 ks = HMAC(SK, x)
    k_reset = compute_hash(ks_reset + SK)   # 新的辅助密钥 k = H(ks || SK)
    # 发送密钥重置消息
    reset_message = json.dumps({"reset_key_x": x.hex()})
    sock.sendto(reset_message.encode('utf-8'), (rev_ip, port))  
    print(f"发送密钥重置消息：{reset_message}")
    #log_message(f"发送密钥重置消息：{reset_message}")
    
    # 重传密钥重置的消息
    max_retries = 10        # 最多重传 10 次
    retries = 0             # 计数
    while retries < max_retries:
        # 开始计时
        #start_time = time.time()
        #while time.time() - start_time < timeout:
        # 接收响应
        response = receive_resetkey(sock, rev_ip, ks_reset)
        if response:            # 规定时间内收到响应
            print("收到响应，密钥重置成功")
            print(f"重置后发送密钥：{ks_reset.hex()}")
            print(f"重置后密钥k'：{k_reset.hex()}")
            return ks_reset, k_reset
        
        # 超时未收到响应
        retries += 1
        print("超时未收到响应，开始重传重置密钥消息...")
        sock.sendto(reset_message.encode('utf-8'), (rev_ip, port))  

    # 失败超过10次，重置密钥失败
    print("重置密钥失败，通信断开，如需通信，重启认证。")
    return 0, 0

# 接收重置密钥确认消息
def receive_resetkey(sock, rev_ip, ks_reset):
    try:
        while True:
            data, addr = sock.recvfrom(1024)  # 接收响应数据
            message_receive = json.loads(data.decode()) 
            ack_ip = addr[0]

            # 是否为来自接收方的响应
            if ack_ip != rev_ip:
                continue
            # 判断是否是重置密钥的响应  {"reset_key": H(kr)}
            if "reset_key" in message_receive:
                received_hash = message_receive["reset_key"]
                received_hash = bytes.fromhex(received_hash)
                # 计算 ks 的哈希值
                expected_hash = compute_hash(ks_reset)
                    # 检查 H(kr) 是否等于 H(ks)
                if received_hash == expected_hash:
                    print("密钥验证成功，收到有效响应，确认重置密钥")
                    return True
                else:
                    print("密钥哈希值不匹配，忽略该响应")
                    return  # 继续等待有效响应
    except socket.timeout:
        print("超时，没有收到有效的密钥重置响应")
        return False     
    
# 收到 响应 则返回响应的数据  超时返回False
def receive_response(sock, rev_ip):
    try:
        data, addr = sock.recvfrom(1024)  # 接收响应数据
        message_receive = json.loads(data.decode()) 
        ack_ip = addr[0]
                #是否为来自接收方的响应
        if ack_ip != rev_ip:
            return False 
        # 判断是否是ack响应
        if "ackj" in message_receive:
            #print(f"收到响应：{data.decode()}")
            log_message(f"收到响应：{data.decode()}")
            return message_receive
        return False        #无效响应
    except Exception:  
        return False 
    



