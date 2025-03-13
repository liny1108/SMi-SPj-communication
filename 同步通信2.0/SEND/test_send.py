import os
import time
import json
import base64
import socket
import random
import string
import hashlib
import send_message
#send_message.communication_flow(sock, rev_ip, ks: bytes, k: bytes, SK: bytes, message: str, timeout: int = 5)

def log_message(message):
    """ 将消息写入日志文件 """
    with open("send_message_log.txt", "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

# 计算哈希值的函数  字节类型
def compute_hash(data: bytes):
    return hashlib.sha256(data).digest() 

# 生成测试消息的函数
def generate_test_messages(num_messages=5):
    test_messages = [
        f"Test message {i}: {os.urandom(8).hex()}" for i in range(1, num_messages + 1)
    ]
    return test_messages

# 启动会话
def test_send(sock, port, rev_ip, ks, k, SK):
    
    # 生成测试消息
    n = 5
    test_messages = generate_test_messages(n)

    start = time.time()
    # 依次发送测试消息
    for msg in test_messages:
        #print(f"\n发送消息: {msg}")
        log_message(f"\n发送消息: {msg}")
        ks, k = send_message.communication_flow(sock, port, rev_ip, ks, k, SK, msg)  # 发送消息，更新密钥
        if ks == 0 or k == 0:   # 密钥重置失败
            print("通信异常，结束会话")
            return
        #print("准备发送下一消息")
        #print(f"下一发送密钥ks：{ks.hex()}")
        #print(f"下一个k：{k.hex()}")
        #time.sleep(2)

    print("测试完毕")
    end = time.time()
    all_time = ( end - start ) * 1000
    avg_time = all_time / len(test_messages)  # 计算平均时间

    print(f"发送{ n }条消息总时间：{all_time:.4f} ms")
    print(f"平均每条消息发送时间: {avg_time:.4f} ms")
    return
