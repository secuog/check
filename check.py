import argparse
import re
import socket
import threading
import requests
import scapy.all
from scapy.layers.inet import ICMP, IP
import time

# 文件路径
path = ''
# 微步
url = 'https://api.threatbook.cn/v3/scene/ip_reputation'
# mykey
key = 'e04d518b2e74487c9f771cd51a42192c095ce70ced5e4d8d968d9a41b3e7d4f1'


# 文件提取字典 取出IP 数量不能大于50 去重  计数
def api(param):
    query = {
        "apikey": key,
        "resource": param
    }
    time.sleep(0.5)
    response = requests.request("GET", url, params=query)
    print("严重级别" + response.json()["data"][param]["severity"])
    print("运营商" + response.json()["data"][param]["basic"]["carrier"])
    print("ip信息" + response.json()["data"][param]["basic"]["location"]["country"] +
          response.json()["data"][param]["basic"]["location"]["province"])
    print("是否恶意" + str(response.json()["data"][param]["is_malicious"]))
    print("可信度" + response.json()["data"][param]["confidence_level"])


def icmpscan(param):
    # 目标主机是否存活
    a1, a2 = scapy.all.sr(IP(dst=param) / ICMP(), timeout=20)
    for snd, rcv in a1:
        # snd发送 rcv接受
        print(rcv.sprintf("ICMP判断 %IP.src% is alive"))


def socket_port(ip, port):
    # 目标开放端口探测
    for port in range(port, port + 50):
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((ip, port))
            print(f"port: {port} 可用")
            s.close()
        except:
            pass
        time.sleep(3)


def ip1(param):
    # socket获取ip
    ip = socket.gethostbyname(param)
    print(ip)





if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("param", type=str, help="ip或者域名")
    parser.add_argument("-s", action="store_true", help="ICMP判断是否存活")
    parser.add_argument("-a", action="store_true", help="调用微步")
    parser.add_argument("-d", action="store_true", help="目标开放端口探测")
    parser.add_argument("-f", action="store_true", help="根据域名获取IP")
    args = parser.parse_args()
    if args.s:
        icmpscan(args.param)
    elif args.a:
        api(args.param)
    elif args.d:
        for i in range(1, 5000, 50):
            threading.Thread(target=socket_port, args=(args.param, i)).start()
    elif args.f:
        ip1(args.param)
