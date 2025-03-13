import hashlib
import os
import base64
import json
import socket
import pandas as pd
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

# 哈希计算  32字节
def calculate_hash(data):
    # 如果是字符串类型，则先编码为字节类型
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()  

# 异或操作  字节类型
def xor_bytes(byte_data1, byte_data2):

    len1 = len(byte_data1)
    len2 = len(byte_data2)
    # 如果长度不一致，填充较短的数据
    if len1 < len2:
        byte_data1 = byte_data1.ljust(len2, b'\x00')  # 填充byte_data1
    elif len1 > len2:
        byte_data2 = byte_data2.ljust(len1, b'\x00')  # 填充byte_data2

    return bytes([b1 ^ b2 for b1, b2 in zip(byte_data1, byte_data2)])   # 返回字节数据

# 加密函数，模拟对称加密  返回字符串
def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_ECB)      # AES加密  使用 ECB 模式
    padded_data = pad(data, AES.block_size)  # 数据填充到块大小
    enc_data = cipher.encrypt(padded_data)   # 加密数据
    return base64.b64encode(enc_data).decode('utf-8')  

# 发送数据包到电表
def send_to_sm(Mi, SMi_ip, sock):
    # 发送 { Mi }
    message = {'Mi': Mi }
    message_json = json.dumps(message)
    print(f"向电表发送的消息：{message_json}")    
    # 发送数据包    
    sock.sendto(message_json.encode('utf-8'), (SMi_ip, 50001))  # 发送到指定IP和端口

# 将 Qi 存入 csv 文件
def save_qi_to_csv(Qi):
    file_path = "dynamic_validation_table.csv"
    # 创建 DataFrame，Qi0 为空
    Qi=Qi.hex()
    new_entry = pd.DataFrame({"Qi": [Qi], "Qi0": [""]})

    try:
        # 尝试读取现有的 csv 文件
        df = pd.read_csv(file_path)
        if df.empty:  # 处理空的 csv 文件
            df = pd.DataFrame(columns=["Qi", "Qi0"])  # 创建空的 DataFrame
        
        # 追加新数据
        df = pd.concat([df, new_entry], ignore_index=True)
    except FileNotFoundError:
        # 如果文件不存在，创建新的 DataFrame
        df = new_entry

    # 写回
    df.to_csv(file_path, index=False)
    print(f"Qi 已存入 {file_path}")

# 服务提供商：接收智能电表发送的{IDi, r1}，计算加密数据Mi
def spj_register(IDj, s, SPj_ip):

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SPj_ip, 50001))  # 监听本地端口消息
    IDj = IDj.encode('utf-8')
    s = s.encode('utf-8')

    try:
        print("服务提供商SPj等待接收智能电表的消息...")

        data, addr = sock.recvfrom(1024)  # 接收消息

        # 提取IDi r1
        message = json.loads(data.decode('utf-8'))   # 解析JSON消息
        IDi = message.get('IDi', None)               # 提取IDi  字符串
        IDi = IDi.encode('utf-8')                    # 转字节
        r1 = bytes.fromhex(message.get('r1', None))  # 提取r1 16进制字符串转为字节
        SMi_ip = addr[0]  # 提取电表的 IP 地址

        print(f"服务提供商SPj接收到的信息: {{'IDi': {IDi}, 'r1': {r1.hex()} }}")

        # 计算加密数据 Mi Mi=Es((IDi ⊕ h( IDj||s))||(r1 ⊕ IDi))
        hash_idj_s = calculate_hash(IDj + s)    # h( IDj || s ) 32字节
        xor1 = xor_bytes(IDi, hash_idj_s)       # IDi ⊕ h(IDj || s) 32字节
        xor2 = xor_bytes(r1, IDi)               # r1 ⊕ IDi  32字节
        
        # 加密 ( (IDi ⊕ h( IDj||s))||(r1 ⊕ IDi) )
        Mi = encrypt_data(s, xor1 + xor2)   # base64编码字符串
        print(f"服务提供商SPj计算的Mi: {Mi}")
        
        # 计算唯一标识符 Qi Qi =h( (IDi || IDj ) ⊕ s ⊕ r1 )
        # (IDi || IDj ) 64字节   s 32字节  r1 32字节
        xors = xor_bytes((IDi + IDj), s)    # (IDi || IDj ) ⊕ s  64字节
        xorr1 = xor_bytes(xors, r1)         # (IDi || IDj ) ⊕ s ⊕ r1  64字节
        Qi = calculate_hash( xorr1 )
        print(f"服务提供商SPj计算的Qi: {Qi.hex()}")

        # 将标识符Qi存到数据库的动态验证表中
        send_to_sm(Mi, SMi_ip, sock)
        print(f"服务提供商SPj更新动态验证表")
        save_qi_to_csv(Qi)
        send_to_sm(Mi, SMi_ip, sock)
        # 返回Mi，模拟通过安全信道发送给智能电表
        return Mi
    finally:
        print("-------end--------")
        sock.close()



IDj = "ServiceProviderServiceProvider01"  # 服务提供商的身份标识
s =   "q49JemhQdITirch7GIxtMtn8ug4R9gKM"  # 主密钥
SPj_ip = '192.168.58.141'  # 服务提供商的IP地址
spj_register(IDj, s, SPj_ip)
