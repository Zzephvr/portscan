---

---

# portscan
一个练习python的小脚本，运用scapy模块进行收发包和解析，同时支持多线程，目前有TCP全连接扫描和syn扫描和默认扫描(仅对常见的端口扫描，可以添加端口列表)

## 1 依赖安装
```
pip install scapy
```
## 2 参数
```
usage:
  python portscan.py [option]
option:
  -u:指定ip或域名
  -s:使用syn扫描,需要root权限
  -c:使用TCP全连接扫描
  -d:对同目录下"default_port.txt"里的常见端口进行syn扫描,需要root权限,可以修改添加端口
  -t:指定线程数,默认20线程
  -p:指定端口范围,配合"-s"或"-c"使用,中间用空格隔开
  -h:查看帮助
```

## 3 示例
```
python portscan.py -u 127.0.0.1 -s -p 80 80
python portscan.py -u www.baidu.com -d
```



## 4 意见反馈

*请联系邮箱:fishcleo10@outlook.com
