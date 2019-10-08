## centos7 安装配置


#### 1.sslib安装

```
cd /etc/yum.repos.d/

wget https://copr.fedorainfracloud.org/coprs/librehat/shadowsocks/repo/epel-7/librehat-shadowsocks-epel-7.repo

yum update

yum install shadowsocks-libev
```

#### 2. obfs安装

```
sudo yum install gcc autoconf libtool automake make zlib-devel openssl-devel asciidoc xmlto libev-devel

git clone https://github.com/shadowsocks/simple-obfs.git

cd simple-obfs

git submodule update --init --recursive

cd src 
```

#### 3.修改编译obfs

```
wget new obfs_http.c

cd ../

./autogen.sh
./configure && make
sudo make install


systemctl stop firewalld.service
```


#### 4. 配置运行

###### server

```
root@kali:~cat  /etc/shadowsocks-libev/config.json 
{
    "server":["::1", "0.0.0.0"],
    "server_port":8080,
    "local_address":"0.0.0.0",
    "local_port":1080,
    "password":"password",
    "timeout":60,
    "method":"chacha20-ietf-poly1305"
}


ss-server -c /etc/shadowsocks-libev/config.json --plugin obfs-server --plugin-opts "obfs=http"

```

###### client

```
{
    "server":["::1", "192.168.219.133"],
    "server_port":8080,
    "local_address":"0.0.0.0",
    "local_port":1080,
    "password":"password",
    "timeout":60,
    "method":"chacha20-ietf-poly1305"
}

ss-local -c /etc/shadowsocks-libev/config.json --plugin obfs-local --plugin-opts "obfs=http;obfs-host=192.168.219.133;obfs-uri=/Manage;http-method=POST"

```
