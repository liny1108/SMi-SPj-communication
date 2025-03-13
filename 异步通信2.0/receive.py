import json
import time
import hmac
import socket
import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

def log_message(message):
    """ 将消息写入日志文件 """
    with open("receive_message_log.txt", "a", encoding="utf-8") as log_file:
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
key_max = 10  # 最多存储 10 个 kr

# 存储处理过的消息序号i
received_identifiers = set()
key_store = {}      # 存储 {"i": kr}
j_max = 1           # 记录当前kr解密的消息序号

# 计算哈希值  32字节
@timing_decorator
def compute_hash(data: bytes):
    return hashlib.sha256(data).digest()

# 计算 HMAC  32字节
@timing_decorator
def hmac_kdf(SK: bytes, data: bytes, length: int = 32):
    return hmac.new(SK, data, hashlib.sha256).digest()[:length]

# 解密消息  返回字节
@timing_decorator
def decrypt_message(kr: bytes, enc_data: bytes):
    enc_data = base64.b64decode(enc_data)     # Base64 解码
    n = b'123456789012'          # 固定值 12字节
    #n = enc_data[:12]  # 提取Nonce
    ciphertext = enc_data[12:]
    cipher = AES.new(kr, AES.MODE_CTR, nonce=n)   # AES CTR模式
    dec_data = cipher.decrypt(enc_data)           # 解密
    return dec_data                               # 字节类型

# 发送 ACK 响应
def send_ack(sock, port, ack_ip, id):
    ack_message = json.dumps({"ackj": id})
    #ack_message = json.dumps({"ack": id})      # 发送无效响应，模拟密钥重置
    sock.sendto(ack_message.encode('utf-8'), (ack_ip, port))
    #print(f"发送 ACK: {id}")
    log_message(f"发送 ACK: {id}")

# 检查时间戳是否在有效窗口内
def is_timestamp_valid(ti: int):
    current_time = int(time.time())
    return current_time - TIME_WINDOW <= ti <= current_time

# 监听并处理接收到的消息
def listen_for_messages(sock, port, SK, kr, k):
    global j_max
    processed_messages = 0      # 记录处理的消息总数
    total_processing_time = 0   # 记录解密 n 条消息的总时间（ms）
    sock.settimeout(120)        # 2分钟超时
    # p = 1
    while True:
        try:
            # time.sleep(10)  # 模拟延迟，导致重传机制触发
            data, addr = sock.recvfrom(1024)        # 接收数据
            ack_ip = addr[0]
            message = json.loads(data.decode())     # 解析 JSON
            #print(f"收到消息：{message} ;来自 {addr}")
            log_message(f"收到消息：{message} ;来自 {addr}")
            msg_start_time = time.time() * 1000     # 记录当前时间（毫秒）
            processed_messages += 1                 # 记录处理的消息数量

            # 发送方请求重置密钥
            if "reset_key_x" in message:
                x = bytes.fromhex(message["reset_key_x"])
                kr = hmac_kdf(SK, x)            # kr = HMAC(SK, x)
                k = compute_hash(kr + SK)       # k  = H(kr || SK)
                print(f"重置后接收密钥：{kr.hex()}")
                print(f"重置后密钥k'：{k.hex()}")

                reset_response = json.dumps({"reset_key": compute_hash(kr).hex()})
                sock.sendto(reset_response.encode('utf-8'), (ack_ip, port))
                #print("密钥已重置，发送确认消息。")

                # 重置相关状态
                key_store.clear()               # 清空之前存的密钥 kr
                j_max = 1                       # 重置消息编号
                received_identifiers.clear()    # 清空已接收的消息记录
                print("密钥已重置，存储的密钥和编号已清空，发送确认消息。")

                # 计算单条消息处理时间
                msg_end_time = time.time() * 1000                    # 记录结束时间（毫秒）
                msg_processing_time = msg_end_time - msg_start_time  # 计算执行时间（毫秒）
                total_processing_time += msg_processing_time         # 累计总处理时间
                continue

            # 提取数据
            id = message.get("j")  
            Ci = message.get("Ci")          # 字符类型
            Tag = message.get("Tag")        # 字符类型
            ti = message.get("ti")          # int

            # if p == 1 and id < 5:         # 模拟信息乱序到达 存kr_1-kr_4
            #     continue
            # p = 0 
            
            # 格式不对，丢弃
            if not all([isinstance(id, int),Ci, Tag, isinstance(ti, int)]):
                print("收到的消息格式不正确，丢弃。")
                continue
            
            # 转换数据格式
            Ci = Ci.encode('utf-8')     # 转字节
            Tag = bytes.fromhex(Tag)    # 转字节

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
            if id in received_identifiers:      
                print("检测到重传数据包，发送 ACK。")
                send_ack(sock, port, ack_ip, id)
                continue

            # 不是重传数据包

            # 该消息的密钥已存在，直接取出解密
            if id < j_max:
                #print(f"id < j_max 使用存储的密钥kr_id ")
                log_message(f"id < j_max 使用存储的密钥kr_id ")
                if id in key_store:
                    kr_id = key_store.pop(id)
                    decrypted_message = decrypt_message(kr_id, Ci)
                    #print(f"解密后的消息 (id={id})：{decrypted_message.decode('utf-8')}")
                    received_identifiers.add(id)        # 存储数据包标识符
                    send_ack(sock, port, ack_ip, id)          # 发送响应
                else:
                    print(f"消息 {id} 过时，密钥已删除，无法解密，丢弃。")

                # 计算单条消息处理时间
                msg_end_time = time.time() * 1000                    # 记录结束时间（毫秒）
                msg_processing_time = msg_end_time - msg_start_time  # 计算执行时间（毫秒）
                total_processing_time += msg_processing_time         # 累计总处理时间
                continue

            # 直接用当前kr解密，并更新kr,k
            if id == j_max:
                #print(f"id == j_max 使用当前密钥kr解密")
                log_message(f"id == j_max 使用当前密钥kr解密")
                decrypted_message = decrypt_message(kr, Ci)
                #print(f"解密后的消息 (id={id})：{decrypted_message.decode('utf-8')}")
                log_message(f"解密后的消息 (id={id})：{decrypted_message.decode('utf-8')}")
                received_identifiers.add(id)        # 存储数据包标识符
                send_ack(sock, port, ack_ip, id)          # 发送响应
                # 更新密钥
                kr = hmac_kdf(kr, k)      # Kr' = HMAC(Kr, k)
                k = compute_hash(kr + k)  # k'  = H(Kr' || k)
                j_max += 1

                # 计算单条消息处理时间
                msg_end_time = time.time() * 1000                    # 记录结束时间（毫秒）
                msg_processing_time = msg_end_time - msg_start_time  # 计算执行时间（毫秒）
                total_processing_time += msg_processing_time         # 累计总处理时间
                continue

            # id > j_max 后续消息先到，需要更新密钥并存储  
            steps = id - j_max                      # 需要更新step次得到当前消息id的密钥kr
            total_kr = len(key_store) + steps       # 如果更新密钥，一共存total_kr个密钥

            # 超过可存储的密钥时，拒绝更新密钥 忽略该消息
            if total_kr > key_max:
                #print(f"消息 {id} 需要 {steps} 次密钥更新，当前存储 {len(key_store)} 个 Kr，新存 {steps} 个，总数 {total_kr} 超过存储上限 {key_max}，丢弃。")
                log_message(f"消息 {id} 需要 {steps} 次密钥更新，当前存储 {len(key_store)} 个 Kr，新存 {steps} 个，总数 {total_kr} 超过存储上限 {key_max}，丢弃。")
                continue

            # 更新密钥以计算新的 kr
            #print("id > j_max 更新密钥并存储部分密钥")
            log_message("id > j_max 更新密钥并存储部分密钥")
            kr_temp, k_temp = kr, k
            for _ in range(steps):                       # 更新steps次，得到用于解密当前消息的密钥 
                key_store[j_max] = kr_temp               # 存消息j_max对应的kr
                kr_temp = hmac_kdf(kr_temp, k_temp)      # Kr' = HMAC(Kr, k)
                k_temp = compute_hash(kr_temp + k_temp)  # k'  = H(Kr' || k)
                j_max += 1

            # 解密当前消息
            decrypted_message = decrypt_message(kr_temp, Ci)
            #print(f"解密后的消息：{decrypted_message.decode('utf-8')}")
            # 存储数据包标识符
            received_identifiers.add(id)
            # 发送 ACK
            send_ack(sock, port, ack_ip, id)
            

            # 更新密钥，解密j_max对应的kr,k
            j_max += 1
            kr = hmac_kdf(kr_temp, k_temp) 
            k = compute_hash(kr + k_temp) 
            # 计算单条消息处理时间
            msg_end_time = time.time() * 1000                       # 记录结束时间（毫秒）
            msg_processing_time = msg_end_time - msg_start_time     # 计算执行时间（毫秒）
            total_processing_time += msg_processing_time            # 累计总处理时间
                
            #operation_times["total_time"] =  operation_times['compute_hash'] + operation_times['decrypt_message'] + operation_times['hmac_kdf']

            # print("操作时间统计:")
            # print(f"哈希计算时间 (Th): {operation_times['compute_hash'] / 1000:.3f} us")
            # print(f"解密时间 (Te): {operation_times['decrypt_message'] / 1000:.3f} us")
            # print(f"HMAC时间 (Thmac): {operation_times['hmac_kdf'] / 1000:.3f} us")
            # print(f"本次成功接收消息总时间: {operation_times['total_time'] / 1000:.3f} us")

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


# # 初始化服务提供商（接收端）
# if __name__ == "__main__":
#     IDj = "ServiceProviderServiceProvider01"  # 服务提供商的身份标识
#     s =   "q49JemhQdITirch7GIxtMtn8ug4R9gKM"  # 主密钥
#     SPj_ip = '192.168.58.141'  # 服务提供商的IP地址

#     # 生成初始密钥
#     SK, ks, kr = derive_keysp.derive_key(IDj, s, SPj_ip)
#     k = compute_hash(ks + SK)  # 初始 k=H(ks || SK)

#     # 创建 UDP 服务器
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.bind((SPj_ip, 50001))  # 绑定端口 50001
#     print("服务提供商监听中，等待接收消息...")
#     # 开始监听消息
#     listen_for_messages(sock, SK, kr, k)
#     sock.close()
