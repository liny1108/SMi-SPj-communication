import os
import time
import json
import socket
import hashlib
import threading
import send_message
#send_message.communication_flow(sock, rev_ip, ks: bytes, k: bytes, SK: bytes, message: str, timeout: int = 5)
def log_message(message):
    """ 将消息写入日志文件 """
    with open("send_message_log.txt", "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

key_reset_event = threading.Event()     # 密钥重置成功的信号
stop_sending_event = threading.Event()  # 密钥开始重置的信号（暂停发送接收消息）
stop_event = threading.Event()          # 终止通信、退出线程的信号

# 计算哈希值的函数  字节类型
def compute_hash(data: bytes):
    return hashlib.sha256(data).digest() 

# 生成测试消息
def generate_test_messages(num_messages=5):
    return {i: f"Test message {i}: {os.urandom(16).hex()}" for i in range(1, num_messages + 1)}

# 消息管理器
# pending_messages记录未发送以及发送未收到响应的消息
# unconfirmed_messages记录已发送未响应的消息 
class MessageManager:
    def __init__(self):
        self.unconfirmed_messages = {}
        self.pending_messages = set()
        self.lock = threading.Lock()

    def add_message(self, message_id, Ci):      # 发送消息，加入已发送未响应消息 message_id为发送序号
        with self.lock:
            # Ci:该消息的密文 send_time:判断是否需要重传 retry_count:记录重传次数
            self.unconfirmed_messages[message_id] = {"Ci": Ci, "send_time": time.time(), "retry_count": 0}

    def remove_message(self, message_id):       # 收到响应，删除相关信息
        with self.lock:
            if message_id in self.unconfirmed_messages:
                del self.unconfirmed_messages[message_id]

    def get_unconfirmed_messages(self):         # 获取字典，用于判断是否重传或密钥重置
        with self.lock:
            return self.unconfirmed_messages.copy()
        
    def clear_unconfirmed_messages(self):       # 密钥重置、清空已发送未确认消息
        with self.lock:
            self.unconfirmed_messages.clear()

    def add_pending_messages(self, message_ids):    # 记录未发送以及发送未收到响应的消息原始序号
        with self.lock:
            self.pending_messages.update(message_ids)

    def remove_pending_message(self, message_id):   # 收到响应，删除该消息序号
        with self.lock: 
            self.pending_messages.discard(message_id)

# 发送消息 添加到字典unconfirmed_messages
def send(sock, port, rev_ip, ks, k, Sk, message, message_id, message_manager):
    Ci, ks, k = send_message.send_data(sock, port, rev_ip, ks, k, Sk, message, message_id)   # 发送消息
    message_manager.add_message(message_id, Ci)     # 加入已发送未响应消息
    return ks,k

# 监听响应的线程
def listen_for_responses(sock, rev_ip, message_manager):
    global message_map  # 全局映射表，用于找到响应消息原始序号
    #try:    
    while not stop_event.is_set():
        if stop_sending_event.is_set():     # 需要重置密钥，暂停监听
            continue
        # 调用函数接收响应，返回json解码后的字符串
        response = send_message.receive_response(sock, rev_ip)
        if response :      
            # 收到响应ack
            if "ackj" in response:
                msg_id = response['ackj']               # 获取响应序号
                original_id = message_map.get(msg_id)   # 查找消息的原始序号
                #print(f"收到响应acki，准备删除未响应集合对应的消息")
                log_message(f"收到响应acki，准备删除未响应集合对应的消息")
                if original_id is not None:
                    if msg_id in message_manager.unconfirmed_messages: 
                        message_manager.remove_message(msg_id)               # 从已发送未收到响应的消息字典中删除（发送序号）
                    if original_id in message_manager.pending_messages: 
                        message_manager.remove_pending_message(original_id)  # 从所有未收到响应的消息集合中移除（原始序号）
                #print("删除完成，继续监听....")
                log_message("删除完成，继续监听....")
    return        
    # except Exception as e:
    #     print(f"监听错误: {e}，重启监听线程...")
    #     time.sleep(2)  # 避免频繁重启

# 定期检查未确认消息 超时未响应则重传，重传超过5次开始重置密钥
def check_unconfirmed_messages(sock, port, rev_ip, message_manager, SK):
    global ks, k                    # 使 ks, k 变为全局变量
    lock = threading.Lock()
    while not stop_event.is_set():
        time.sleep(5)               # 每5秒检查一次
        for msg_id, msg_data in message_manager.get_unconfirmed_messages().items():  
            if time.time() - msg_data["send_time"] > 5:             # 超时未确认
                if msg_data["retry_count"] < 5:                     # 允许最多5次重传
                    #print(f"重传消息 {msg_id}")
                    log_message(f"重传消息 {msg_id}")
                    #retransmit_message(sock, rev_ip, SK: bytes, Ci: bytes)
                    send_message.retransmit_message(sock, port, rev_ip, SK, msg_data["Ci"], msg_id)
                    msg_data["send_time"] = time.time()             # 重新计时
                    msg_data["retry_count"] += 1                    # 重传次数+1
                else:
                    print(f"消息 {msg_id} 多次重传失败，尝试重置密钥...")
                    #log_message(f"消息 {msg_id} 多次重传失败，尝试重置密钥...")
                    stop_sending_event.set()                        # 密钥重置中...
                    #reset_keys(sock, rev_ip, SK: bytes)
                    with lock:
                        ks, k = send_message.reset_keys(sock, port, rev_ip, SK)  # 重置密钥，成功返回重置后的新密钥，否则返回 (0,0)
                    message_manager.clear_unconfirmed_messages()    # 清空已发送未响应消息
                    key_reset_event.set()       # 密钥重置完成，通知主线程
                    if ks == 0 or k == 0:
                        print("密钥重置失败，终止通信")
                        #log_message("密钥重置失败，终止通信")
                        sock.close()
                        return  # 终止通信
                    else:
                        stop_sending_event.clear()  # 密钥重置成功，继续发送消息接收响应
                        break
                    #key_reset_event.set()  
                    #stop_sending_event.clear()  # 清除事件
    return

ks = None
k = None

# 启动会话
def test_send(sock, port, rev_ip, ks_s, ksend, SK):
    
    global message_id, message_map
    global ks,k
    ks = ks_s
    k = ksend
    message_id = 1
    message_map = {}  # 初始化映射表
    n = 20
    test_messages = generate_test_messages(n)   # 生成测试消息
    message_manager = MessageManager()      #初始化
    message_manager.add_pending_messages(test_messages.keys())

    # 创建线程
    listener_thread = threading.Thread(target=listen_for_responses, args=(sock, rev_ip, message_manager),daemon=True)
    checker_thread = threading.Thread(target=check_unconfirmed_messages, args=(sock, port, rev_ip, message_manager, SK),daemon=True)

    # 启动线程
    listener_thread.start()
    checker_thread.start()

    start_time = time.time()  # 记录开始时间
    
    while True:
        for i in list(message_manager.pending_messages):  # 所有要发送的消息（未发送以及发送未响应的消息）
            if stop_sending_event.is_set():               # 开始重置密钥，停止发送消息
                    break  
            msg = test_messages[i]
            #print(f"发送消息 {i}: {msg}")
            log_message(f"发送消息 {i}: {msg}")
            ks, k = send(sock, port, rev_ip, ks, k, SK, msg, message_id, message_manager)
            message_map[message_id] = i  # 记录映射关系 发送序号 message_id -> 消息序号 i
            message_id += 1 

        while True:
            if key_reset_event.is_set():        # 密钥重置完成
                key_reset_event.clear()         # 清除信号
                if ks == 0 or k == 0:           # 密钥重置失败，终止通信
                    stop_event.set()            # 通知所有线程退出
                    listener_thread.join()
                    checker_thread.join()   
                    sock.close()
                    return      
                else:                           # 密钥重置成功
                    print(f"重置后发送密钥：{ks.hex()}")
                    print(f"重置后密钥k'：{k.hex()}")
                    message_map.clear()         # 清空映射
                    message_id = 1              # 重新编号（发送序号）
                    break                       # 退出循环，继续发消息

            elif not message_manager.pending_messages:          # 消息已全部发送并收到响应

                end_time = time.time()                          # 记录结束时间
                total_time = (end_time - start_time) * 1000     # 计算发送 n 条消息的总时间  毫秒
                avg_time = total_time / len(test_messages)      # 计算平均时间

                print("所有消息已确认，测试完成。")
                print(f"发送{n}条消息总发送时间: {total_time:.4f} ms")
                print(f"平均每条消息发送时间: {avg_time:.4f} ms")
                stop_event.set()            # 通知所有线程退出
                listener_thread.join()
                checker_thread.join()      
                sock.close()                # 测试完成 通信结束
                return
