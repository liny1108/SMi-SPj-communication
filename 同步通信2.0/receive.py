import socket
import json
import time
import hmac
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def log_message(message):
    """ 将消息写入日志文件 """
    with open("send_message_log.txt", "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

def timing_decorator(func):
    """ 装饰器用于计算函数执行时间 """
    def wrapper(*args, **kwargs):
        # start_time = time.perf_counter_ns()  # 纳秒
        start_time = time.time() * 1000      # 毫秒
        result = func(*args, **kwargs)
        # end_time = time.perf_counter_ns()    # 纳秒
        end_time = time.time() * 1000        # 毫秒
        elapsed_time = end_time - start_time
        operation_times[func.__name__] += elapsed_time
        return result
    return wrapper

# 记录各个操作的时间
operation_times = {
    "compute_hash": 0,          # 哈希
    "decrypt_message": 0,       # 解密
    #"encrypt_data": 0,         # 加密
    "hmac_kdf": 0,              # HMAC计算
    "total_time": 0             # 总时间
}
# 配置滑动窗口大小（单位：秒）
TIME_WINDOW = 30

# 存储处理过的消息序号
received_identifiers = set()

# 计算哈希值  32字节
@timing_decorator
def compute_hash(data: bytes):
    return hashlib.sha256(data).digest()

# 计算 HMAC  32字节
@timing_decorator
def hmac_kdf(SK: bytes, data: bytes, length: int = 32):
    return hmac.new(SK, data, hashlib.sha256).digest()[:length]

# # 解密消息  返回字节
# @timing_decorator
# def decrypt_message(kr: bytes, enc_data: bytes):
#     enc_data = base64.b64decode(enc_data)     # Base64 解码
#     #n = b'123456789012'          # 固定值 12字节
#     n = enc_data[:12]  # 提取Nonce
#     ciphertext = enc_data[12:]
#     cipher = AES.new(kr, AES.MODE_CTR, nonce=n)   # AES CTR模式
#     dec_data = cipher.decrypt(enc_data)           # 解密
#     return dec_data                               # 字节类型
@timing_decorator
def decrypt_message(kr: bytes, enc_data: bytes):
    try:
        enc_data = base64.b64decode(enc_data)   # Base64 解码
        n = b'123456789012'                     # 固定值 12字节
        # n = enc_data[:12]  # 提取Nonce
        # ciphertext = enc_data[12:]  # 提取密文
        cipher = AES.new(kr, AES.MODE_CTR, nonce=n)  # 使用 AES-CTR 模式
        dec_data = cipher.decrypt(enc_data)  # 解密
        #print(f"解密成功")
        log_message(f"解密成功")
        return dec_data  # 返回字节类型
    except (UnicodeDecodeError, ValueError) as e:
        #print(f"解密失败，丢弃该消息。错误原因：{e}")
        log_message(f"解密失败，丢弃该消息。错误原因：{e}")
        return None  # 返回 None，表示解密失败
    except Exception as e:
        #print(f"解密过程中发生未知错误：{e}")
        log_message(f"解密过程中发生未知错误：{e}")
        return None

# 发送 ACK 响应
def send_ack(sock, port, ack_ip, packet_id):
    ack_message = json.dumps({"ack": packet_id})
    #ack_message = json.dumps({"aaa": id})      # 发送无效响应，模拟密钥重置
    sock.sendto(ack_message.encode('utf-8'), (ack_ip, port))
    #print(f"发送 ACK")
    log_message(f"发送 ACK")

# 检查时间戳是否在有效窗口内
def is_timestamp_valid(ti: int):
    current_time = int(time.time())
    return current_time - TIME_WINDOW <= ti <= current_time

# 监听并处理接收到的消息
def listen_for_messages(sock, port, SK, kr, k):
    processed_messages = 0      # 记录处理的消息总数
    total_processing_time = 0   # 记录解密 n 条消息的总时间（ms）
    sock.settimeout(120)        # 2分钟超时
    while True:
        try:
            data, addr = sock.recvfrom(1024)        # 接收数据
            ack_ip = addr[0]
            message = json.loads(data.decode())     # 解析 JSON
            #print(f"收到消息：{message} ;来自 {addr}")
            log_message(f"收到消息：{message} ;来自 {addr}")
            msg_start_time = time.time() * 1000     # 记录当前时间（毫秒）
            processed_messages += 1                 # 记录处理的消息数量

            # 收到重置密钥的请求
            if "reset_key_x" in message:
                x = bytes.fromhex(message["reset_key_x"])
                kr = hmac_kdf(SK, x)        # kr = HMAC(SK, x)
                k = compute_hash(kr + SK)   # k  = H(kr || SK)
                reset_response = json.dumps({"reset_key": compute_hash(kr).hex()})      # 发送H(kr) 确认重置密钥
                sock.sendto(reset_response.encode('utf-8'), (ack_ip, port))
                print("密钥已重置，发送确认消息。")
                print(f"重置后接收密钥kr：{kr.hex()}")
                print(f"重置后辅助密钥k：{k.hex()}")
                # 计算重置密钥消息处理时间
                msg_end_time = time.time() * 1000                    # 记录结束时间（毫秒）
                msg_processing_time = msg_end_time - msg_start_time  # 计算执行时间（毫秒）
                total_processing_time += msg_processing_time         # 累计总处理时间
                continue

            # 记录一般消息处理开始时间
            msg_start_time = time.time()

            # 提取数据
            Ci = message.get("Ci")      # 字符串
            Tag = message.get("Tag")    # 字符串
            ti = message.get("ti")      # int
            
            # 格式不对，丢弃
            if not all([Ci, Tag, isinstance(ti, int)]):
                print("收到的消息格式不正确，丢弃。")
                continue
            
            # 转换数据格式
            Ci = Ci.encode('utf-8')     # 转字节类型
            Tag = bytes.fromhex(Tag)    # 转字节类型

            # 检查时间戳是否在有效窗口内
            if not is_timestamp_valid(ti):
                print(f"无效时间戳：{ti}，丢弃消息。")
                continue

            # 计算 Tag 并验证
            computed_tag = hmac_kdf(SK, Ci + ti.to_bytes(4, 'big'))
            if computed_tag != Tag:
                print("Tag 验证失败，丢弃消息。")
                continue

            # 检查是否是重传数据包
            packet_id = (Ci.decode())                   # 用 (Ci) 作为唯一标识符
            if packet_id in received_identifiers:       # 重复数据包
                #print("检测到重传数据包，发送 ACK。")
                log_message("检测到重传数据包，发送 ACK。")
                send_ack(sock, port, ack_ip, packet_id)
                continue

            # 不是重传数据包

            # 存储数据包标识符
            received_identifiers.add(packet_id)

            # 解密消息
            decrypted_message = decrypt_message(kr, Ci)
            #print(f"解密后的消息：{decrypted_message.decode('utf-8')}") 
            log_message(f"解密后的消息：{decrypted_message.decode('utf-8')}") 

            # print(f"更新前接收密钥ks：{kr.hex()}")
            # print(f"更新前密钥k：{k.hex()}")

            # 更新密钥 kr',k'
            kr_new = hmac_kdf(kr, k)          # Kr' = HMAC(Kr, k)
            k_new = compute_hash(kr_new + k)  # k' = H(Kr' || k)

            # 更新密钥
            kr, k = kr_new, k_new
            # 发送响应
            send_ack(sock, port, ack_ip, packet_id)

            # 计算消息处理时间
            msg_end_time = time.time()
            msg_processing_time = (msg_end_time - msg_start_time) * 1000        # 转换为毫秒
            total_processing_time += msg_processing_time                        # 累计总处理时间

            # 主要操作总时间
            # operation_times["total_time"] =  operation_times['compute_hash'] + operation_times['decrypt_message'] + operation_times['hmac_kdf']
            # print("操作时间统计:")
            # print(f"哈希计算时间 (Th): {operation_times['compute_hash'] / 1000:.3f} us")
            # print(f"解密时间 (Te): {operation_times['decrypt_message'] / 1000:.3f} us")
            # print(f"HMAC时间 (Thmac): {operation_times['hmac_kdf'] / 1000:.3f} us")
            # print(f"本次成功接收消息主要操作总时间: {operation_times['total_time'] / 1000:.3f} us")
        
        except socket.timeout:
            if processed_messages > 0 :
                avg_processing_time = (total_processing_time / processed_messages)
            else: 
                avg_processing_time = 0
            print(f" 超过 2 分钟未收到新消息，统计如下：")
            print(f" 共处理 {processed_messages} 条消息")
            print(f" 平均每条消息的解密时间: {avg_processing_time:.4f} ms\n")
            break  # 退出

        except json.JSONDecodeError:
            print("JSON 解析失败，丢弃消息。")
        except Exception as e:
            print(f"处理消息时发生错误：{e}")
