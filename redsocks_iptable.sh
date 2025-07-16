# # 1. 创建专用链（可选但推荐）
iptables -t nat -N REDSOCKS_DNS

# # 2. 排除本地和私有网络（避免循环）
# iptables -t nat -A REDSOCKS_DNS -d 0.0.0.0/8 -j RETURN
# iptables -t nat -A REDSOCKS_DNS -d 127.0.0.0/8 -j RETURN
# iptables -t nat -A REDSOCKS_DNS -d 192.168.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 0.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 10.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 100.64.0.0/10 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 127.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 169.254.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 172.16.0.0/12 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 192.168.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 198.18.0.0/15 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 224.0.0.0/4 -j RETURN
iptables -t nat -A REDSOCKS_DNS -d 240.0.0.0/4 -j RETURN


# 4. 应用到OUTPUT链
iptables -t nat -A OUTPUT -p tcp -j REDSOCKS_DNS
# #sudo iptables -t nat -L -v --line-numbers


# DNS重定向（强制走TCP）
#iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 9992
# HTTP\HTTPS 重定向
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 9999
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 9999

#清空表：sudo iptables -t nat -F
#清空链：sudo iptables -t nat -X

