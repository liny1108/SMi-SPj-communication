# SM-SP-communication
同步通信和异步通信的电表文件夹/服务提供商文件夹下的python文件基本一样。  
同步通信和异步通信的区别只在receive.py、Test_Send.py、Send_message.py  
├── 电表（SM）  
│   ├── smi_register.py  # 处理电表注册  
│   ├── smi_sksm.py  # 电表身份认证与密钥协商  
│   ├── SMI.py  # 连接服务提供商，发送/接收消息  
│   ├── Test_SK_derive_time.py  # 认证与密钥派生时间测试  

├── 服务提供商（SP）  
│   ├── spj_register.py  # 处理注册请求  
│   ├── spj_sksp.py  # 认证与密钥协商  
│   ├── SPJ.py  # 连接电表，发送/接收消息  
│   ├── Test_SK_derive_time.py  # 认证与密钥派生时间测试  
  
├── SEND  
│   ├── Test_Send.py  # 生成并发送测试消息  
│   ├── Send_message.py  # 发送各类消息监听响应 
  
├── derive_key.py  # 密钥派生  
├──  receive.py  # 监听并处理接收的消息  

运行方式  
  在两个虚拟机上运行。服务提供商比电表先运行。  
  通信前先执行注册代码。  
  `python3 spj_register.py`  
  `python3 smi_register.py`  
  测试认证与密钥派生过程的时间：  
  服务提供商   
  `python3 Test_SK_derive_time.py`  
  电表  
  `python3 Test_SK_derive_time.py`  
  测试发送/接收消息的时间：  
  服务提供商  
  `python3 SPJ.py`  
  电表  
 `python3 SMI.py`  
  
