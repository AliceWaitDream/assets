#!/bin/bash
set -eu

[[ "$EUID" -ne '0' ]] && echo "Error:This script must be run as root!" && exit 1;

if ! command -v apt-get &> /dev/null; then
  echo "Error: apt-get command not found. Please make sure you are using a Debian-based system."
  exit 1
fi

public_ipv6=$(ip a show dev venet0 | grep -Eo 'inet6 ([0-9a-fA-F]*:){3}[0-9a-fA-F]*' | awk '{print $2}')
destUrl="learn.microsoft.com"
destPort="443"
ssPasswd=""
uuid_Tor=""
uuid_direct=""
shortId=""
isShow="false"
isSshd="false"

# 处理命令行参数
while [[ $# -gt 0 ]]; do
  case "$1" in
    -sshd)
      isSshd="true"
      ;;
    -show)
      isShow="true"
      ;;
    --destUrl)
      shift
      destUrl="$1"
      ;;
    --destPort)
      shift
      destPort="$1"
      ;;
    --ssPasswd)
      shift
      ssPasswd="$1"
      ;;
    --uuid_Tor)
      shift
      uuid_Tor="$1"
      ;;
    --uuid_direct)
      shift
      uuid_direct="$1"
      ;;
    --shortId)
      shift
      shortId="$1"
      ;;
    *)
      # 未知参数
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
  # 移动到下一个参数
  shift 
done

if [ "$isSshd" = "true" ]; then
  if [ ! -d "/root/.ssh" ]; then
    mkdir /root/.ssh/
    chmod 700 /root/.ssh/
  fi
  echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC07eKpk7E+Ti76p+UcmE6YzQ9SoFKmegCBTcKxgX8geUu7UKjxOXqDN7NoKEPmp/W/fsGNiTqg1saPgR/+M7l5fiP3cMr3m+9YLHdtD9dk5UcR51S1y2Miqxa42MlVcvgfP37acSQWLrMqOdZzMg8mtW2q9Em0oKNA4HuLYALIvCWEU7NyeBeALxOfNzG4YpEVlGyl5zC4QJGhxlwvSizo0B4NqFCcyfP7GHZbswRISRLa2ZcXv/O5d4fuLsN1d1ruEZWmIed//20L+P4G6RP4uu4kEm+hFaxF7Z9una1661v4ISRqd11f6Gv0pGepHlhSlBllAcUDBWSx3XpfLPzl+uuA5RrmgkaIoscpOPjHaKuRl94ryHjmhO0KQUvulppUd41ijX4Gi7yao69KuQIMwpmhE9wSTfqDXtG9f3x6G6gcqw8tJL3oOCgnldqJV26/1oDDKpBEUsMg2KXbbdJqFpYh2AYLUfyPnYkPPrcxymJA6c6QBO9TBdls6WJ51mGg6MiRmmIpFSxjYOdmMoCBPR17SnwF+CUaY4oE6ecCPMR93U5kdNVUlI5+u3DHnKsawY1yNX3UxYBw6KxzAu87R4AiivlrBBxF+CHH5xbP/+gTfwwvOyIaXq1WSOG6DOCFVR5ljmLN9G+o542N7BA4f+0w5tTA79NsU20Sd6MK6w== adminuser@localhost" >/root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys

  # 设定SSH端口为2222
  sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
  # 禁止密码登录
  sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

  systemctl restart sshd
fi

if command -v apache2 &> /dev/null; then
    # Stop `apache2`. 
    service apache2 stop
    # 列出所有与apache2相关的软件包
    packages=$(dpkg -l | grep apache2 | awk '{print $2}')
    # 使用for循环遍历packages变量中的每个软件包，并使用dpkg命令进行卸载
    for package in $packages; do
        dpkg --purge $package
    done
    apt autoremove

    # 运行whereis命令并将输出存储到变量中
    apache2_files=$(whereis apache2)
    # 使用空格作为分隔符，将输出的文件路径拆分成数组
    IFS=' ' read -r -a files_array <<< "$apache2_files"
    # 遍历数组并删除文件
    for file_path in "${files_array[@]}"; do
        # 忽略空值和首个元素（因为首个元素是命令名）
        if [[ -n "$file_path" && "$file_path" != "apache2:" ]]; then
            rm -rf "$file_path"
        fi
    done
fi

apt update
apt install -y vim curl wget tor

# Install xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --beta

# Create Key of reality
xray x25519 > /root/key_reality

# 提取`Private key` `Public key`
privateKey=$(grep "Private key" /root/key_reality | awk '{print $NF}')
publicKey=$(grep "Public key" /root/key_reality | awk '{print $NF}')

# 判断`ssPasswd`合法
if [ ${#ssPasswd} -ne 16 ]; then
  ssPasswd=$(openssl rand -base64 16)
fi

# 使用正则表达式判断`shortId`是否合法
if ! [[ $shortId =~ ^([0-9a-fA-F]{2}){1,8}$ ]]; then
  shortId=$(openssl rand -hex 8)
fi

# 使用正则表达式判断`uuid_Tor`是否合法
if ! [[ $uuid_Tor =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  uuid_Tor=$(xray uuid)
fi
# 使用正则表达式判断`uuid_direct`是否合法
if ! [[ $uuid_direct =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  uuid_direct=$(xray uuid)
fi

# Set xray
cat >/usr/local/etc/xray/config.json<<EOF
{
  "log": null,
  //"log": {
  //  "access": "/var/log/xray/access.log",
  //  "error": "/var/log/xray/error.log",
  //  "loglevel": "debug"
  //},
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "domain": [
          "geosite:private"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "domain": [
          "geosite:category-ads-all"
        ],
        "outboundTag": "blocked"
      }
    ]
  },
  "dns": {
    "servers": [
      "https+local://1.1.1.1/dns-query",
      "https+local://8.8.8.8/dns-query",
      "localhost"
    ]
  },
  "inbounds": [
    // vmess+ws 80port
    {
      "listen": "0.0.0.0",
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$uuid_Tor",
            "alterId": 0,
            "email": "vmess@TorSocks"
          },
          {
            "id": "$uuid_direct",
            "alterId": 0,
            "email": "vmess@direct"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/"
        }
      },
      "sniffing": {
        "enabled": false,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "tag": "vmess-in80"
    },
    // reality 443port
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$uuid_Tor",
            "flow": "xtls-rprx-vision",
            "email": "vless@Tor"
          },
          {
            "id": "$uuid_direct",
            "flow": "xtls-rprx-vision",
            "email": "vless@direct"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false, // 选填，若为 true，输出调试信息
          "dest": "$destUrl:$destPort", // 必填，格式同 VLESS fallbacks 的 dest
          "xver": 0, // 选填，格式同 VLESS fallbacks 的 xver
          "serverNames": [ // 必填，客户端可用的 serverName 列表，暂不支持 * 通配符
            "learn.microsoft.com"
          ],
          "privateKey": "$privateKey", // 必填，执行 ./xray x25519 生成
          "minClientVer": "", // 选填，客户端 Xray 最低版本，格式为 x.y.z
          "maxClientVer": "", // 选填，客户端 Xray 最高版本，格式为 x.y.z
          "maxTimeDiff": 0, // 选填，允许的最大时间差，单位为毫秒
          "shortIds": [ // 必填，客户端可用的 shortId 列表，可用于区分不同的客户端
            "$shortId"
            // "" // 若有此项，客户端 shortId 可为空
            // "0123456789abcdef" // 0 到 f，长度为 2 的倍数，长度上限为 16
          ]
        }
      },
      "sniffing": {
        "enabled": false,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "tag": "reality-in"
    },
    // ipv6 only direct
    {
      "listen": "0.0.0.0",
      "port": 3306,
      "protocol": "shadowsocks",
      "settings": {
        "method": "2022-blake3-aes-128-gcm",
        "password": "$ssPasswd",
        "network": "tcp,udp",
        "email": "shadowsocks@direct"
      },
      "sniffing": {
        "enabled": false,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "tag": "ss-in"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ]
}
EOF

systemctl restart xray.service

# Set tor
cat >/etc/tor/torrc<<EOF
ExcludeExitNodes {cn},{hk},{mo},{kp},{sy},{pk},{cu},{vn},{ru},{by},{sg},{th},{ph},{my}
ExcludeNodes {cn},{hk},{mo},{kp},{sy},{pk},{cu},{vn},{ru},{by},{sg},{th},{ph},{my}
ExitNodes {us}
StrictNodes 1

SocksPort 127.0.0.1:8118
SocksPort 127.0.0.1:9050
SocksPort 127.0.0.1:9150
EOF

systemctl restart tor

if [ "$isShow" = "true" ]; then
cat >/root/woiden_xray.result<<EOF
# reality 443port direct
vless://$uuid_direct@[$public_ipv6]:443?security=reality&encryption=none&pbk=$publicKey&headerType=none&fp=chrome&spx=%2F&type=tcp&flow=xtls-rprx-vision-udp443&sni=$destUrl&sid=$shortId#woiden
EOF
fi
