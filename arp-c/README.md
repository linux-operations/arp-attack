akarpoison
==========

ARP攻击有2种形式
第一种是欺骗你的服务器，告诉你网关的MAC是另外一个。
第二种是欺骗网关，告诉网关你的服务器的MAC是另外一个。
对于第一种可以用arp -s 网关IP 网关MAC命令来设置静态arp记录防御
对于第二种可以使用下面的方法处理

## 编译
1. 先编译 libnet(用make install安装到/usr/local/lib/libnet.a)
2. gcc arpoison.c /usr/local/lib/libnet.a -o arpoison

## 用法

`sudo arpoison Usage: -i <device> -d <dest IP> -s <src IP> -t <target MAC> -r <src MAC> [-a] [-w time between packets] [-n number to send]`

## 参数说明
* -i 指定发送arp包的网卡接口eth0
* -d 192.168.90.1 指定目的ip为192.168.90.1
* -s 192.168.90.102 指定源ip为192.168.90.102
* -t ff:ff:ff:ff:ff:ff 指定目的mac地址为ff:ff:ff:ff:ff:ff(arp广播地址)
* -r 08:00:27:08:69:58 指定源mac地址为08:00:27:08:69:58
* -w 等待时间
* -n 发送包的数目

## 例子

* 防御ARP欺骗

```
sudo ./arpoison -i eth0 -d 192.168.90.1 -s 192.168.90.102 -t ff:ff:ff:ff:ff:ff -r 08:00:27:08:69:58
```

* 进行arp欺骗

```
sudo ./arpoison -i eth0 -d 192.168.90.102 -s 192.168.90.1 -t ff:ff:ff:ff:ff:ff -r 08:00:27:08:69:58
```

----------------------

	ARPoison v0.5 B

		By Buer (sbuer@secureworks.com)

Description
-----------

   This program sends out a custom ARP REPLY packet with the hardware and 
protocol address information of your choosing. Since ARP is a stateless protocol, 
most operating systems will gladly update their ARP cache with whatever
information you send them in your hand-crafted packet.
 
Notes
-----

   Requires Libnet -- http://www.packetfactory.net/Projects/Libnet/
