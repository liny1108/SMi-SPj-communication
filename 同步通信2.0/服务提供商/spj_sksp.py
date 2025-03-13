import json
import random
import hashlib
import socket
import time
import os
import base64
import pandas as pd
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

def timing_decorator(func):
    """ 装饰器用于计算函数执行时间 """
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time_ms = (end_time - start_time) * 1000  # 转换为毫秒
        operation_times[func.__name__] += elapsed_time_ms
        return result
    return wrapper

# 记录各个操作的时间
operation_times = {
    "hash_function": 0,     # 哈希
    "decrypt_data": 0,      # 解密
    "encrypt_data": 0,      # 加密
    "total_time": 0         # 总时间
}

# 生成高熵随机数
def generate_random_number():
    return os.urandom(32)  # 32字节 

# 哈希计算函数  字节类型
@timing_decorator
def hash_function(data):
    # 如果是字符串类型，则先编码为字节类型
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()  # 哈希计算  

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

# 加密 返回字符串
@timing_decorator
def encrypt_data(key, data):
    # 如果是字符串类型，则先编码为字节类型
    if isinstance(key, str):
        key = key.encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)                 # AES加密  使用 ECB 模式
    padded_data = pad(data, AES.block_size)             # 数据填充到块大小
    enc_data = cipher.encrypt(padded_data)              # 加密数据
    return base64.b64encode(enc_data).decode('utf-8')   # base64编码 转为字符串

# 解密   字节类型  
@timing_decorator
def decrypt_data(key, enc_data):
    cipher = AES.new(key, AES.MODE_ECB)  # AES ECB
    decrypted_padded = cipher.decrypt(enc_data)  # 解密数据
    decrypted_data = unpad(decrypted_padded, AES.block_size)  # 取消填充
    return decrypted_data  # 字节类型

# 拆分Mi   字节类型
def parse_decrypted_Mi(decrypted_data):
    IDi_h = decrypted_data[:32]     # IDi’ ⊕ h( IDj’ || s’ ) 
    r1_IDi = decrypted_data[32:64]  # r1’ ⊕ IDi’
    return IDi_h, r1_IDi

# 从动态验证表加载数据
def load_dynamic_validation_table(file_path="dynamic_validation_table.csv"):
    # 加载动态验证表（Qi, Qi0）到DataFrame
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        df = pd.DataFrame(columns=["Qi", "Qi0"])
    return df

# 更新动态验证表
def update_dynamic_validation_table(file_path="dynamic_validation_table.csv", df=None):
    # 将新的动态验证表更新到csv文件
    df.to_csv(file_path, index=False)
    print("动态验证表已更新.")


# 发送数据包Mi到电表
def send_to_sm(message, SMi_ip, sock):

    # 将字典转换为JSON格式，模拟打包数据
    message_json = json.dumps(message)
    print(f"向电表发送的消息：{message_json}")
    
    # 发送数据包    
    sock.sendto(message_json.encode('utf-8'), (SMi_ip, 50001))  # 发送到指定IP和端口

# 服务提供商主流程
def main(sock, IDj, s, SPj_ip):

    start = time.time()
    # 获取动态验证表
    df = load_dynamic_validation_table()
    IDj = IDj.encode('utf-8')
    s = s.encode('utf-8')
    #        
    print("认证过程——服务提供商SPj等待接收智能电表的消息...")

    # 收到Mi、Xi
    data, addr = sock.recvfrom(1024)        # 接收消息，最大1024字节
    SMi_ip =  addr[0] 
    message_json = data.decode("utf-8")     # 字节转字符串
    message = json.loads(message_json)      # 解析 JSON 数据
    Mi = base64.b64decode(message["Mi"])    # Base64 解码，得到 AES 加密的原始数据
    Xi = bytes.fromhex(message["Xi"])       # 十六进制字符串转换回字节数据

    # 用s解密Mi
    decrypted_mi = decrypt_data(s, Mi)      # 字节
    IDi_h, r1_IDi = parse_decrypted_Mi(decrypted_mi)  
    # IDi_h  = IDi’ ⊕ h( IDj’ || s’ )
    # r1_IDi = r1’ ⊕ IDi’

    # IDi* = IDi_h ⊕ h(IDj || s)
    h_IDj_s = hash_function(IDj + s)
    # IDi*   32字节
    IDi_star = xor_bytes(IDi_h, h_IDj_s)
    # r1*  r1_IDi ⊕ IDi*
    r1_star = xor_bytes(r1_IDi, IDi_star)

    # Qi' = h((IDi* || IDj) ⊕ s ⊕ r1*)   
    xors = xor_bytes( IDi_star + IDj, s)  # (IDi* || IDj) ⊕ s
    xorr1 = xor_bytes(xors, r1_star)      # (IDi* || IDj) ⊕ s ⊕ r1*
    Qi_prime = hash_function( xorr1 )
    Qi_prime = Qi_prime.hex()

    # 检查动态验证表
    print("检查动态验证表...")
    if Qi_prime in df["Qi"].values:
        print("验证通过，使用现有的 Qi。")  #Qi列
    elif Qi_prime in df["Qi0"].values:
        print("Qi0 匹配，替换 Qi 为 Qi0。") #Qi0列
        df.loc[df["Qi0"] == Qi_prime, "Qi"] = df.loc[df["Qi0"] == Qi_prime, "Qi0"]
    else:
        print("验证失败！终止会话。")
        return

    # r2′ = Xi ⊕ h(IDi* || r1*)
    h_IDi_r1 = hash_function(IDi_star + r1_star)
    r2_prime = xor_bytes(Xi, h_IDi_r1)

    # Mi′ = Es( (IDi* ⊕ h(IDj || s)) || (r2′ ⊕ IDi*) )
    hash_idj_s = hash_function(IDj + s)         # h( IDj || s )
    xor1 = xor_bytes(IDi_star, hash_idj_s)      # IDi ⊕ h(IDj || s)
    xor2 = xor_bytes(r2_prime, IDi_star)        # (r2′ ⊕ IDi*)
    Mi_prime = encrypt_data(s, xor1 + xor2)     # base64编码字符串
    print(f"计算新的Mi′: {Mi_prime}")
    Mi_prime = base64.b64decode(Mi_prime)

    # 生成r3
    r3 = generate_random_number()   # 字节类型

    # k = h(IDi* ⊕ r1* ⊕ r2′)
    IDi_xor_r1 = xor_bytes(IDi_star, r1_star)   # IDi* ⊕ r1*
    r2_xor = xor_bytes(IDi_xor_r1, r2_prime)    # IDi* ⊕ r1* ⊕ r2′
    k = hash_function(r2_xor)                   # 字节类型

    # Authji = Ek( (h( (IDi* ⊕ r2′) || r1*) ⊕ r3) || h(IDi* || r1* || r2′) || Mi′ )
    # (h( (IDi* ⊕ r2′) || r1*) ⊕ r3)
    IDi_xor_r2 = xor_bytes(IDi_star, r2_prime)           # IDi* ⊕ r2′   32字节
    h_IDi_r2_r1 = hash_function(IDi_xor_r2 + r1_star)    # h( (IDi* ⊕ r2′) || r1*)  32字节
    h_xor_r3 = xor_bytes(h_IDi_r2_r1, r3)                # h( (IDi* ⊕ r2′) || r1*) ⊕ r3  32字节

    # h(IDi* || r1* || r2′)
    h_IDi_r1_r2 = hash_function(IDi_star + r1_star + r2_prime)
    # Authji
    Authji= encrypt_data(k, h_xor_r3 + h_IDi_r1_r2 + Mi_prime)   #base64编码字符串
    
    print(f"认证消息 Authji: {Authji}")

    # SKsp = h(IDi* || r1* || r2′ || r3)
    SKsp = hash_function(IDi_star + r1_star + r2_prime + r3)

    sendmessage =  {'Authji': Authji} 
    # 发Authji 给电表
    send_to_sm(sendmessage, SMi_ip, sock)

    # --------等待电表响应------------------

    # 接收电表的认证响应 Authij
    print("等待接收来自电表的认证消息 Authij...")
    # 接收服务提供商的响应消息 字符串

    dataA, addrA = sock.recvfrom(1024)          # 字节类型
    message1 = dataA.decode()
    message1 = json.loads(message1)             # json解码
    Authij = bytes.fromhex(message1['Authij'])  # 16进制字符串转字节
    print(f"接收的 Authij : { Authij.hex() }")

    # Authij == h(SKsp || r3)
    expected_authij = hash_function(SKsp + r3)
    if Authij != expected_authij:
        print("验证失败！终止会话。")
        return

    # 计算新的 Qi 值并更新动态验证表
    # Qinew =h( (IDi* || IDj ) ⊕ s ⊕ r2' )
    xor_ID_s = xor_bytes(IDi_star + IDj, s)     # (IDi* || IDj ) ⊕ s 64字节
    xorr2 = xor_bytes(xor_ID_s, r2_prime)       # (IDi* || IDj ) ⊕ s ⊕ r2'   64字节
    Qinew = hash_function( xorr2 )              # 32字节

    Qinew = Qinew.hex()
    print(f"服务提供商SPj计算的Qi: {Qinew}") 
    # 更新表（Qi,Qi0）-> (Qinew,Qi)
    df.loc[df["Qi"] == Qi_prime, ["Qi", "Qi0"]] = [Qinew, Qi_prime]
    # 更新动态验证表
    update_dynamic_validation_table(file_path="dynamic_validation_table.csv", df=df)

    # Ackji = h((r2′ ⊕ r3) || r1*)
    xor_r2_r3 = xor_bytes(r2_prime, r3)               # (r2′ ⊕ r3)  32字节
    h_r2_r3_r1 = hash_function(xor_r2_r3 + r1_star)   # 32字节
    Ackji = h_r2_r3_r1

    sendmessage2  = {'ACKji': Ackji.hex()}  #字典
    # 发 Ackji 给电表
    send_to_sm(sendmessage2, SMi_ip, sock)

    # 时间
    end = time.time()
    operation_times["total_time"] =  operation_times['hash_function'] + operation_times['decrypt_data'] + operation_times['encrypt_data']
    all_time = ( end - start ) *1000
    print("操作时间统计:")
    print(f"哈希计算时间 (Th): {operation_times['hash_function']:.3f} ms")
    print(f"解密时间 (Td): {operation_times['decrypt_data']:.3f} ms")
    print(f"加密时间 (Te): {operation_times['encrypt_data']:.3f} ms")
    print(f"认证过程主要操作总时间: {operation_times['total_time']:.3f} ms")
    print(f"整个认证过程总时间：{all_time:.3f} ms")
    #return SKsp, operation_times["total_time"]         # 返回主要操作总时间
    return SKsp, all_time, SMi_ip

def run_authentication(sock, IDj, s, SPj_ip):
    # 运行服务提供商的身份认证-密钥协商
    SK, all_time, SMi_ip = main(sock, IDj, s, SPj_ip)
    print(f"共享会话密钥: {SK.hex()}")
    return SK, all_time, SMi_ip
    

# if __name__ == "__main__":

    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # sock.bind((SPj_ip, 50001))  # 监听本地端口消息

    # IDj = "ServiceProviderServiceProvider01"  # 服务提供商的身份标识
    # s =   "q49JemhQdITirch7GIxtMtn8ug4R9gKM"  # 主密钥
    # SPj_ip = '192.168.58.141'    # 服务提供商的IP地址
    # SK=run_authentication(sock, IDj, s, SPj_ip)
    # print(f"共享会话密钥: {SK.hex()}")
