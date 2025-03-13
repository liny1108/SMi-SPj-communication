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

# 发送消息 发{ Ci; Tag; ti }
def send_message(sock, port, rev_ip, Ci: bytes, Tag: bytes, ti: int):
    message = {'Ci': Ci.decode('utf-8'), 'Tag': Tag.hex(), 'ti': ti}
    message_json = json.dumps(message)
    #print(f"发送消息: {message_json}")
    log_message(f"发送消息: {message_json}")
    sock.sendto(message_json.encode('utf-8'), (rev_ip, port))  # 发送到服务提供商

# 计算需要发送的消息
def send_data(sock, port, rev_ip, ks: bytes, k: bytes, SK: bytes, message: str):
    
    Ci = encrypt_message(ks, message)   # 加密消息     Ci 字节类型
    # print(f"发送密钥：{ks.hex()}")
    ti = generate_timestamp()           # 生成时间戳   int 类型
    tag_data = Ci + ti.to_bytes(4, 'big')  
    Tag = hmac_kdf(SK, tag_data)        # 生成消息标签 Tag 字节类型

    # 发送消息  
    send_message(sock, port, rev_ip, Ci, Tag, ti)
    #print(f"首次发送消息")
    
    ks_new = hmac_kdf(ks, k)          # 更新发送密钥 ks' = HMAC(ks, k)
    k_new = compute_hash(ks_new + k)  # 计算新的 k' = H(ks' || k)

    operation_times["total_time"] =  operation_times['compute_hash'] + operation_times['encrypt_message'] + operation_times['hmac_kdf']

    # print("操作时间统计:")
    # print(f"哈希计算时间 (Th): {operation_times['compute_hash']:.3f} ms")
    # print(f"加密时间 (Te): {operation_times['encrypt_message']:.3f} ms")
    # print(f"HMAC时间 (Thmac): {operation_times['hmac_kdf']:.3f} ms")
    # print(f"本次成功发送消息总时间: {operation_times['total_time']:.3f} ms")
    

    # print(f"更新发送密钥ks'：{ks_new.hex()}")
    # print(f"更新密钥k'：{k_new.hex()}")

    return Ci, ks_new, k_new  # 返回密文和新的发送密钥和k'

# 重传消息的函数   {Ci；Tag’； ti’}
def retransmit_message(sock, port, rev_ip, SK: bytes, Ci: bytes):
    
    ti_new = generate_timestamp()                   # 重新生成新的时间戳 ti'
    tag_data_new = Ci + ti_new.to_bytes(4, 'big')   # (Ci || ti')
    Tag_new = hmac_kdf(SK, tag_data_new)            # 计算新的消息标签 Tag' = HMAC(SK, (Ci || ti’))

    # 重新发送消息
    send_message(sock, port, rev_ip, Ci, Tag_new, ti_new)
    #print(f"重新发送消息：{Ci.decode('utf-8')}，{Tag_new.hex()}，时间戳：{ti_new}")
    log_message(f"重新发送消息：{Ci.decode('utf-8')}，{Tag_new.hex()}，时间戳：{ti_new}")

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
    
    # 重传密钥重置的消息
    max_retries = 10     # 最多重传 10 次
    retries = 0          # 计数
    #timeout = 30         # 超时阈值
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
            
        retries += 1
        print("超时未收到响应，开始重传重置密钥消息...")
        sock.sendto(reset_message.encode('utf-8'), (rev_ip, 50001))  

    # 失败超过10次，重置密钥失败
    print("重置密钥失败，通信断开，如需通信，重启认证。")
    return 0, 0

# 收到重置密钥确认消息
def receive_resetkey(sock, rev_ip, ks_reset):
    try:
        while True:
            data, addr = sock.recvfrom(1024)  # 接收响应数据
            message_receive = json.loads(data.decode()) 
            ack_ip = addr[0]

            #是否为来自接收方的响应
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
                    continue  # 继续等待有效响应
    except socket.timeout:
        print("超时，没有收到有效的密钥重置响应")
        return False    
    
# 收到响应 则返回True  超时返回False
def receive_response(sock, rev_ip):
    try:
        while True:
            data, addr = sock.recvfrom(1024)  # 接收响应数据
            message_receive = json.loads(data.decode()) 
            ack_ip = addr[0]
            #是否为来自接收方的响应
            if ack_ip != rev_ip:
                continue
            # 判断是否是ack响应
            if "ack" in message_receive:
                #print(f"收到响应：{data.decode()}")
                log_message(f"收到响应：{data.decode()}")
                return True
    except socket.timeout:
        #print("超时，没有收到有效的 ack 响应")
        log_message("超时，没有收到有效的 ack 响应")
        return False
    
#传输消息 直到收到响应 或 超过重传次数，传输失败
def communication_flow(sock, port, rev_ip, ks: bytes, k: bytes, SK: bytes, message: str):
    sock.settimeout(10)     # 10s超时
    # 发送消息  返回Ci, ks' ,k'
    while True:
        Ci, ks_new, k_new = send_data(sock, port, rev_ip, ks, k, SK, message)  # 发送消息并更新密钥

        max_retries = 5     # 最多重传5次
        retries = 0         # 计数
        while retries < max_retries:
            # 开始计时
            #start_time = time.time()
            #while time.time() - start_time < timeout:
            # 接收响应
            response = receive_response(sock, rev_ip)
            if response:            # 时间内收到响应
                #print("收到响应")
                #log_message("收到响应")
                # print(f"更新后发送密钥：{ks_new.hex()}")
                # print(f"更新后密钥k'：{k_new.hex()}")
                return ks_new, k_new
            
            retries += 1
            #print("超时未收到响应")
            #log_message("超时未收到响应")
            retransmit_message(sock, port, rev_ip, SK, Ci)

        # 失败超过5次，重置密钥并重新发送当前消息
        print("重传失败，认为通信异常，重置密钥并重新发送消息")
        ks, k = reset_keys(sock, port, rev_ip, SK)  # 重置密钥

        #print(f"重置后的密钥 ks={ks.hex()}, k={k.hex()}")

         # 密钥重置失败，直接终止会话
        if ks == 0 or k == 0:
            print("密钥重置失败，终止通信")
            return 0, 0     # 终止通信
        else:
            continue        # 重发当前消息
        # 超过5次 重传失败 返回旧的密钥
        # return ks, k



