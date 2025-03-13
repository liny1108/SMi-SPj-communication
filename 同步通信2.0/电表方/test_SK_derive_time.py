import os
import sys
import time
import socket
import smi_sksm

# 获取当前文件的上一级目录
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# 将上一级目录添加到 sys.path
sys.path.append(parent_dir)
import derive_key

def measure_average_time(n, SMi_ip, SPj_ip):
    total_auth_time = 0         # 认证过程总时间
    total_derive_time = 0       # 密钥派生时间
    total_all_time = 0          # 认证-密钥派生总时间
    
    # 创建 socket 连接
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SMi_ip, 50001))
    
    for _ in range(n):
        SKsm, sk_time = smi_sksm.run_authentication(sock, SMi_ip, SPj_ip)   # sk_time：认证过程总时间
        
        start_time = time.time()
        ks, kr = derive_key.HMAC_keys(SKsm,'SM')    
        end_time = time.time()
        
        derive_time = (end_time - start_time) * 1000     # 密钥派生时间
        all_time = derive_time + sk_time                 # 认证-密钥派生时间
        
        total_auth_time += sk_time
        total_derive_time += derive_time
        total_all_time += all_time
    
    sock.close()
    
    avg_auth_time = total_auth_time / n
    avg_derive_time = total_derive_time / n
    avg_all_time = total_all_time / n
    
    print(f"平均认证时间：{avg_auth_time:.3f} ms")
    print(f"平均密钥派生时间：{avg_derive_time:.3f} ms")
    print(f"平均认证-密钥派生总时间：{avg_all_time:.3f} ms")
    
    return avg_auth_time, avg_derive_time, avg_all_time


if __name__ == "__main__":
    SMi_ip = '192.168.58.140'
    SPj_ip = '192.168.58.141'
    n = 10  # 运行次数
    measure_average_time(n, SMi_ip, SPj_ip)
