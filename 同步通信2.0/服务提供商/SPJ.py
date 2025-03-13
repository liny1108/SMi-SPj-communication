import os
import sys
import socket
import hashlib
import threading
import spj_sksp

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

# 计算哈希值  32字节
def compute_hash(data: bytes):
    return hashlib.sha256(data).digest()

# 初始化服务提供商（接收消息）
if __name__ == "__main__":

    IDj = "ServiceProviderServiceProvider01"    # 服务提供商的身份标识 32字节
    s =   "q49JemhQdITirch7GIxtMtn8ug4R9gKM"    # 主密钥 32字节
    SPj_ip = '192.168.58.141'                   # 服务提供商的IP地址
    
    # 创建 UDP 服务器
    sockrev = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # 用于认证-接收消息
    rport = 50001
    sockrev.bind((SPj_ip, rport))  # 绑定端口 50001 接收消息

    # 生成初始密钥
    print("开始认证，生成初始密钥...")
    SK, sk_time, SMi_ip = spj_sksp.run_authentication(sockrev, IDj, s, SPj_ip)     # 身份认证-密钥协商
    ks, kr = derive_key.HMAC_keys(SK, 'SP')    # 密钥派生
    krev = compute_hash(kr + SK)         # 初始 krev=H(kr || SK)
    ksend = compute_hash(ks + SK)        # 初始 ksend=H(ks || SK)
    print("认证结束，开始通信...")

#---------------------------开始通信------------------------------------------
    #-------------接收消息--------------------
    print("服务提供商监听中，等待接收消息...")
    recv_thread = threading.Thread(target=receive.listen_for_messages, args=(sockrev, rport, SK, kr, krev))    # 创建并启动接收消息的线程
    recv_thread.start()

    # #-------------发送消息--------------------
    sport = 50002
    socksend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # 用于发送消息
    socksend.bind((SPj_ip , sport))                                 # 监听响应

    # 发送测试消息test_send(sock, port, SMi_ip, ks, k, SK)
    test_send.test_send(socksend, sport, SMi_ip, ks, ksend, SK)     # 发送到电表的50002端口，在50002端口监听响应

    
