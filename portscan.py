#!/usr/bin/env python
# coding: utf-8

import argparse
import queue
import socket
import threading
import logging
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import sr, send

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def parse_args():  # 接收命令行参数
    parser = argparse.ArgumentParser(description="例:'python portscanner.py -u www.example.com -s -p 70 80 -t 10'")
    parser.add_argument("-u", "--target_ip", required=True, help="enter URL/IP")
    parser.add_argument("-t", "--thread_num", type=int, default=20, help="thread number,default 20 threads")
    parser.add_argument("-s", "--syn", action="store_true",
                        help="syn scan,please use with '-p'")  # action="store_true",参数可以为空
    parser.add_argument("-p", "--port", nargs='+', type=int, help="please specify the port range, separated by a space")
    parser.add_argument("-T", "--TCP_connect", action="store_true", help="TCP connect scan,please use with '-p'")
    parser.add_argument("-d", "--default", action="store_true",
                        help="scan a list of specified ports,use 'default_port.txt'")
    return parser.parse_args()


def syn_scan(start_port, end_port):  # syn扫描
    while not q.empty():
        i = q.get()
        an, uan = sr(IP(dst=args.target_ip) / TCP(dport=i, flags='S'), timeout=2, verbose=False)
        if len(an) == 0:  # filtered
            pass
        elif an[0][1].getlayer(TCP).flags == 18:  # open
            send(IP(dst=args.target_ip) / TCP(dport=i, flags='R'), verbose=False)
            print(f"[+]{i}号端口开放!")
        elif an[0][1].getlayer(TCP).flags == 20:  # close
            pass
        elif an[0][1].haslayer(ICMP) and an.res[0][1].getlayer(ICMP).type == 3 and an.res[0][1].getlayer(ICMP).code in [
            1, 2, 3, 9, 10, 13]:  # filtered
            pass
        q.task_done()


def connect_scan(start_port, end_port):  # connect扫描
    while not q.empty():
        i = q.get()
        an, uan = sr(IP(dst=args.target_ip) / TCP(dport=i, flags='S'), timeout=2, verbose=False)
        if len(an) == 0:
            pass  # filtered
        elif an[0][1].getlayer(TCP).flags == 18:  # open
            send(IP(dst=args.target_ip) / TCP(dport=i, flags='RA'), verbose=False)
            print(f"[+]{i}号端口开放!")
        elif an[0][1].haslayer(ICMP) and an.res[0][1].getlayer(ICMP).type == 3 and an.res[0][1].getlayer(ICMP).code in [
            1, 2, 3, 9, 10, 13]:
            pass  # filtered
        q.task_done()


def default_scan():
    while not q.empty():
        i = q.get()
        an, uan = sr(IP(dst=args.target_ip) / TCP(sport=17000, dport=i, flags='S'), timeout=2, verbose=False)
        if len(an) == 0:
            pass  # filtered
        elif an[0][1].getlayer(TCP).flags == 18:  # open
            send(IP(dst=args.target_ip) / TCP(dport=i, flags='R'), verbose=False)
            print(f"[+]{i}号端口开放!")
        elif an[0][1].getlayer(TCP).flags == 20:  # close
            pass
        elif an[0][1].haslayer(ICMP) and an.res[0][1].getlayer(ICMP).type == 3 and an.res[0][1].getlayer(ICMP).code in [
            1, 2, 3, 9, 10, 13]:  # filtered
            pass
        q.task_done()


def thread(function_name):
    try:
        threads = []
        for i in range(int(args.thread_num) + 1):
            if args.port:
                t = threading.Thread(target=function_name, args=(args.port[0], args.port[1]))
                threads.append(t)
            elif args.default:
                t = threading.Thread(target=default_scan)
                threads.append(t)
        for j in range(len(threads)):
            t.setDaemon(True)
            threads[j].start()
    except Exception as ee:
        print(ee)
        pass


if __name__ == '__main__':
    args = parse_args()
    q = queue.Queue()
    try:
        args.target_ip = socket.gethostbyname(args.target_ip)
        print("ip地址:" + str(args.target_ip))
        if args.port and not args.default:
            for i in range(args.port[0], args.port[1] + 1):
                q.put(i)
            if args.syn and not args.TCP_connect and args.port:
                thread(syn_scan)
            elif args.TCP_connect and not args.syn and args.port:
                thread(connect_scan)
            else:
                print("参数错误,请使用-h查看帮助!")
        else:
            if args.default and not args.port and not args.TCP_connect and not args.syn:
                with open("default_port.txt", "r", encoding="utf-8") as f:
                    data = f.readlines()
                for i in data:
                    q.put(int(i))
                    thread(default_scan)
            else:
                print("参数错误,请使用-h查看帮助!")
    except Exception as e:
        print(e)
