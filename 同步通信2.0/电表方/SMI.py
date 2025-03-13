import os
import sys
import socket
import hashlib
import threading
import smi_sksm

# 获取当前文件的上一级目录
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# 将上一级目录添加到 sys.path
sys.path.append(parent_dir)
import receive
import derive_key

# 构造SEND目录的路径
send_dir = os.path.join(parent_dir, "SEND")
# 将SEND目录添加到sys.path
sys.path.append(send_dir)
import test_send

# 计算哈希值的函数  字节类型
def compute_hash(data: bytes):
    return hashlib.sha256(data).digest() 

# 启动会话
if __name__ == "__main__":
    
    SMi_ip = '192.168.58.140'       # 电表ip
    SPj_ip = '192.168.58.141'       # 接收方IP
    sport = 50001
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SMi_ip , sport))    # 监听响应

    # 初始密钥derive_key(sock, SMi_ip, SPj_ip)
    print("开始认证，生成初始密钥...")
    SK, sk_time = smi_sksm.run_authentication(sock, SMi_ip ,SPj_ip)     # 身份认证-密钥协商
    ks, kr = derive_key.HMAC_keys(SK, 'SM')    # 密钥派生
    ksend = compute_hash(ks + SK)        # 初始 ksend=H(ks || SK)
    krev = compute_hash(kr + SK)         # 初始 krev=H(kr || SK)
    print("认证结束，开始通信...")

#---------------------------开始通信------------------------------------------
    # #-------------接收消息--------------------
    rport = 50002
    sockrev = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sockrev.bind((SMi_ip, rport))  # 绑定端口 50002  接收来自服务提供商的消息
    print("电表监听中，等待接收消息...")
    recv_thread = threading.Thread(target=receive.listen_for_messages, args=(sockrev, rport, SK, kr, krev))    # 创建并启动接收消息的线程
    recv_thread.start()

    #-------------发送消息--------------------
    # 发送测试消息test_send(sock, port, SMi_ip, ks, k, SK)
    test_send.test_send(sock, sport, SPj_ip, ks, ksend, SK)         # 发送到服务提供商的50001端口，在50001端口监听响应