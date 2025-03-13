import os
import hashlib
import random
import base64
import json
import socket

# 生成高熵随机数  32字节
def generate_random_number():
    return os.urandom(32) 

# 发送数据包到服务提供商
def send_to_spj(IDi, r1, SPj_ip, sock):
    message = {'IDi': IDi, 'r1': r1.hex()}
    message_json = json.dumps(message)      #打包成json
    print(f"向服务提供商发送的消息：{message_json}")

    # 发送数据包    
    sock.sendto(message_json.encode('utf-8'), (SPj_ip, 50001))  

# 接收服务提供商返回的消息Mi
def receive_from_spj(sock, SMi_ip, SPj_ip):

    sock.settimeout(30)  # 10 秒超时，防止卡死
    print("等待接收服务提供商的消息...")
    try:
        data, addr = sock.recvfrom(1024)  # 接收消息，最大1024字节
        sender_ip, sender_port = addr
        # 只处理来自服务提供商的消息
        if sender_ip == SPj_ip:
            # 提取消息内容
            message = json.loads(data.decode('utf-8'))  # 解析JSON消息
            Mi = message.get('Mi', None)  # 提取Mi字段 (base64编码的字符串)
            #print(f"从服务提供商接收到的消息Mi: {Mi}") 
            return Mi   
        else:
            print(f"忽略来自 {sender_ip} 的消息")

    except socket.timeout:
        print("接收超时，未收到服务提供商的响应")
        return None


# 智能电表方：生成r1并发送信息给服务提供商
def smi_register(IDi, SPj_ip):
    # 创建连接
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 存到防篡改设备的数据
    stored_data = None  
    sock.bind((SMi_ip, 50001))  # 绑定端口
    sock.settimeout(10)
    
    try:
        # 生成高熵随机数r1
        r1 = generate_random_number()
        #print(f"智能电表SMi生成的随机数r1: {r1.hex()}")

        # 向服务提供商发送{IDi, r1}
        send_to_spj(IDi, r1, SPj_ip, sock)
        
        # 等待接收Mi
        Mi = receive_from_spj(sock, SMi_ip, SPj_ip)

        if Mi is None:
            print("未能接收到 Mi，注册失败")
            return None
                
        # 存储{ Mi , IDi , r1}到防篡改设备（本地文件）
        stored_data = {'IDi': IDi,'r1': r1.hex(), 'Mi': Mi}
        print(f"智能电表SMi存储的数据: {stored_data}")

        with open("meter_data.json", "w", encoding="utf-8") as f:
            json.dump(stored_data, f, indent=4, ensure_ascii=False)

    except Exception as e:
        print(f"发生错误: {e}")
    finally:
        sock.close()

    return stored_data

SMi_ip = '192.168.58.140'
IDi = "SmartMeterSmartMeterSmartMeter01"  # 电表的身份标识 32字节
SPj_ip = '192.168.58.141'  # 服务提供商的IP地址
smi_register(IDi, SPj_ip)
