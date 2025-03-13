import json
import random
import hashlib
import socket
import time
import os
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def timing_decorator(func):
    """ 装饰器用于计算函数执行时间 """
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        operation_times[func.__name__] += elapsed_time
        return result
    return wrapper

# 记录各个操作的时间
operation_times = {
    "hash_function": 0,     # 哈希
    "decrypt_data": 0,      # 解密
    "total_time": 0         # 总时间
}

# 读取电表的IDi、r1和Mi
def read_meter_data():
    with open("meter_data.json", "r") as f:
        data = json.load(f)
    return data["IDi"], data["r1"], data["Mi"]

# 生成高熵随机数
def generate_random_number():
    return os.urandom(32)  # 32字节 

# 哈希计算函数
@timing_decorator
def hash_function(data):
    # 如果是字符串类型，则先编码为字节类型
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()  # 哈希计算  返回字节类型

# 异或操作  字节类型
def xor_bytes(byte_data1, byte_data2):

    len1 = len(byte_data1)
    len2 = len(byte_data2)
    # 如果长度不一致，填充较短的数据
    if len1 < len2:
        byte_data1 = byte_data1.ljust(len2, b'\x00')  # 填充byte_data1
    elif len1 > len2:
        byte_data2 = byte_data2.ljust(len1, b'\x00')  # 填充byte_data2

    # 对两个字节数据执行异或操作
    return bytes([b1 ^ b2 for b1, b2 in zip(byte_data1, byte_data2)])   # 返回字节数据

# 发送数据包到服务提供商
def send_to_spj(message, SPj_ip, sock):
    message_json = json.dumps(message)
    print(f"向服务提供商发送的消息：{message_json}")
    # 发送数据包    
    sock.sendto(message_json.encode('utf-8'), (SPj_ip, 50001))  # 发送到指定IP和端口

# 接收服务提供商的响应消息  json格式字符串
def receive_from_sp(sock, timeout = 10):
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(1024)
        return data.decode()
    except socket.timeout:
        print("接收超时，重新启动认证过程...")
        return None

# 解密  返回字节类型
@timing_decorator
def decrypt_data(key, enc_data):
    cipher = AES.new(key, AES.MODE_ECB)          # AES ECB
    decrypted_padded = cipher.decrypt(enc_data)  # 解密数据
    decrypted_data = unpad(decrypted_padded, AES.block_size)  # 取消填充
    return decrypted_data  # 字节类型

# 拆分Authji   字节类型
def parse_decrypted_authji(decrypted_data):
    h_xor_r3 = decrypted_data[:32]   # h(IDi* ⊕ r2′ || r1*) ⊕ r3
    h_value = decrypted_data[32:64]  # h(IDi* || r1* || r2′)
    Mi_1 = decrypted_data[64:]       # Mi′
    return h_xor_r3, h_value, Mi_1

# 更新电表文件 meter_data.json  r2,Mi_star 是字符串
def update_meter_data(r2, Mi_star):
    with open("meter_data.json", "r") as f:
        data = json.load(f)
    data["r1"] = r2
    data["Mi"] = Mi_star
    with open("meter_data.json", "w") as f:
        json.dump(data, f, indent=4)
    print("电表数据已更新.")

# 主流程
def main(sock, SMi_ip, SPj_ip):

    start = time.time()

    # 获取IDi,r1,Mi
    IDi, r1, Mi = read_meter_data() # 都是字符串类型
    IDi = IDi.encode('utf-8')       # 字节
    r1 = bytes.fromhex(r1)          # 字节

    # 生成高熵随机数r2
    r2 = generate_random_number()   # 字节

    # 计算 Xi = r2 ⊕ h(IDi || r1)
    hash_IDi_r1 = hash_function(IDi + r1)   # 字节
    Xi = xor_bytes(r2, hash_IDi_r1)         # Xi=r2 ⊕ h ( IDi || r1) 字节类型

    message = {'Mi': Mi, 'Xi': Xi.hex()}
    # 发送 Mi、Xi 给服务提供商
    send_to_spj(message, SPj_ip, sock)

    # --------等待服务提供商的响应----------------

    # 等待接收认证消息 Authji
    print("等待接收来自服务提供商的认证消息 Authji...")
    message_json = receive_from_sp(sock)      # json格式字符串
    if message_json is None:
        return None
    
    # 计算 k' = h(IDi ⊕ r1 ⊕ r2)
    xor_IDi_r1 = xor_bytes(IDi, r1)  
    xor_IDi_r1_r2 = xor_bytes(xor_IDi_r1, r2)  
    k = hash_function(xor_IDi_r1_r2)  # 计算哈希值

    message_receive = json.loads(message_json)            # 解析 JSON 数据
    Authji = base64.b64decode(message_receive["Authji"])  # Base64 解码，得到 AES 加密的原始数据
    # 解密
    decrypted_data = decrypt_data(k, Authji)
    # 拆成三部分
    h_xor_r3, h_value, Mi_1 = parse_decrypted_authji(decrypted_data) 
    # h_xor_r3 h( (IDi** ⊕ r2*) || r1**) ⊕ r3’
    # h_value h(IDi** || r1** || r2*)
    # Mi_1 Mi*


    # 验证 h(IDi || r1 || r2) 
    h_IDi_r1_r2 = hash_function(IDi + r1 + r2)
    if h_value != h_IDi_r1_r2:
        print("验证失败！会话终止。")
        # sock.close
        # 重启会话
        print("重启认证")
        return None 

    # r3* = h_xor_r3 ⊕ h((IDi ⊕ r2) || r1 )
    IDi_xor_r2 = xor_bytes(IDi, r2)         # (IDi ⊕ r2)
    h_r1 = hash_function(IDi_xor_r2 + r1)   # h((IDi ⊕ r2) || r1 )
    r3_star = xor_bytes(h_xor_r3, h_r1)     # r3 32字节

    # SKsm=h( IDi || r1 || r2 || r3*)
    SKsm = hash_function(IDi + r1 + r2 + r3_star)  # 32字节

    # Authij = h(SKsm || r3*)
    Authij = hash_function(SKsm + r3_star)
    message1 = {'Authij': Authij.hex()} 
    # 发送 Authij 
    send_to_spj(message1, SPj_ip, sock)

    # --------等待服务提供商响应------------------

    # ACKji
    print("等待接收来自服务提供商的确认消息 ACKji...")
    message_json2 = receive_from_sp(sock)               # json字符串
    if message_json2 is None:
        return None
    message_receive2 = json.loads(message_json2)        # 解析 JSON 数据
    Ackji = bytes.fromhex(message_receive2["ACKji"])    # 16进制字符串转字节

    # Ackji == h((r2 ⊕ r3*) || r1) ?
    r2_xor_r3 = xor_bytes(r2, r3_star)
    ackji1 = hash_function(r2_xor_r3 + r1)
    if Ackji != ackji1:
        print("确认消息验证失败！会话终止。")
        #sock.close
        #重启认证
        print("重启认证")
        return None

    # 更新电表数据
    r2 = r2.hex()       # 16进制字符串
    Mi_1 = base64.b64encode(Mi_1).decode('utf-8')  
    update_meter_data(r2, Mi_1)
    print("认证成功，建立会话密钥 SKsm。")
    

    # 时间
    end = time.time()
    operation_times["total_time"] =  operation_times['hash_function'] + operation_times['decrypt_data'] 
    all_time = (end - start) * 1000 
    print("操作时间统计:")
    print(f"哈希计算时间 (Th): {operation_times['hash_function']:.3f} ms")
    print(f"解密时间 (Td): {operation_times['decrypt_data']:.3f} ms")
    print(f"认证过程主要操作总时间: {operation_times['total_time']:.3f} ms")
    print(f"整个认证过程总时间：{all_time:.3f} ms")
    #return SKsm, operation_times["total_time"]       # 返回主要操作总时间
    return SKsm, all_time

def run_authentication(sock, SMi_ip, SPj_ip):
    # 运行身份认证-密钥协商
    while True:
        SKsm, all_time = main(sock, SMi_ip, SPj_ip)  # 调用 main 并获取返回值
        if SKsm is not None:
            return SKsm, all_time   # 认证成功后退出循环
        print("认证失败，重启认证...")
        


# # 启动主流程
# if __name__ == "__main__":
          #创建连接
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.bind((SMi_ip, 50001))  # 绑定端口
    # SMi_ip = '192.168.58.140'
    # SPj_ip = '192.168.58.141'  # 服务提供商的IP地址
    # SKsm = run_authentication(sock,SMi_ip, SPj_ip)
    # print(f"共享会话密钥: {SKsm.hex()}")
