# WireGuard Easy

[![Build & Publish Docker Image to Docker Hub](https://github.com/xwvike/wg-easy/actions/workflows/deploy.yml/badge.svg?branch=v14)](https://github.com/xwvike/wg-easy/actions/workflows/deploy.yml)
[![Lint](https://github.com/xwvike/wg-easy/actions/workflows/lint.yml/badge.svg?branch=v14)](https://github.com/xwvike/wg-easy/actions/workflows/lint.yml)
![Docker](https://img.shields.io/docker/pulls/xwvike/wg-easy.svg)
[![Sponsor](https://img.shields.io/github/sponsors/weejewel)](https://github.com/sponsors/WeeJeWel)
![GitHub Stars](https://img.shields.io/github/stars/xwvike/wg-easy)

你找到了在任何 Linux 主机上安装和管理 WireGuard 的最简方法！

<p align="center">
  <img src="./assets/screenshot.png" width="802" />
</p>

## 功能
* 一体化：WireGuard + Web UI。
* 安装简易，使用简单。
* 列出、创建、编辑、删除、启用与禁用客户端。
* 展示客户端的二维码。
* 下载客户端配置文件。
* 查看哪些客户端已连接的统计信息。
* 为每个已连接客户端提供 Tx/Rx 图表。
* 支持 Gravatar。
* 自动切换浅色 / 深色模式。
* 多语言支持。
* UI_TRAFFIC_STATS（默认关闭）。

## 需求

* 内核支持 WireGuard 的主机（所有现代内核）。
* 安装了 Docker 的主机。

## 版本

此分支仅用于 WireGuard Easy 的 v14 版本发布。
如需更新版本，请查看 [master 分支](https://github.com/wg-easy/wg-easy/tree/master)。
尽管上游已将新功能迁移到 v15+，我会继续维护并扩展 v14。

## 安装

### 1. 安装 Docker

如果尚未安装 Docker，请运行：

```bash
curl -sSL https://get.docker.com | sh
sudo usermod -aG docker $(whoami)
exit
```

然后重新登录。

### 2. 运行 WireGuard Easy

要自动安装并运行 wg-easy，只需执行：

```
  docker run -d \
  --name=wg-easy \
  -e LANG=de \
  -e WG_HOST=<🚨YOUR_SERVER_IP> \
  -e PASSWORD_HASH=<🚨YOUR_ADMIN_PASSWORD_HASH> \
  -e PORT=51821 \
  -e WG_PORT=51820 \
  -v ~/.wg-easy:/etc/wireguard \
  -p 51820:51820/udp \
  -p 51821:51821/tcp \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  --sysctl="net.ipv4.conf.all.src_valid_mark=0" \
  --sysctl="net.ipv4.ip_forward=1" \
  --restart unless-stopped \
  ghcr.io/xwvike/wg-easy
```

> 💡 将 `YOUR_SERVER_IP` 替换为你的 WAN IP，或动态 DNS 主机名。
>
> 💡 将 `YOUR_ADMIN_PASSWORD_HASH` 替换为用于登录 Web UI 的 bcrypt 密码哈希。参阅 [How_to_generate_an_bcrypt_hash.md](./How_to_generate_an_bcrypt_hash.md) 了解如何生成该哈希值。

Web UI 将可通过 `http://0.0.0.0:51821` 访问。

> 💡 你的配置文件会保存在 `~/.wg-easy`。

WireGuard Easy 也可以通过 Docker Compose 启动 —— 直接下载
[`docker-compose.yml`](docker-compose.yml)，进行必要的调整，然后执行
`docker compose up --detach`。

### 3. 赞助

喜欢这个项目吗？[请为 Emile 买杯啤酒！](https://github.com/sponsors/WeeJeWel) 🍻

## 可选项

可以在 `docker run` 命令中使用 `-e KEY="VALUE"` 设置环境变量来配置下列选项。

| 环境变量 | 默认值 | 示例 | 描述                                                                                                                                          |
| - | - | - |------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PORT` | `51821` | `6789` | Web UI 的 TCP 端口。                                                                                                                                 |
| `WEBUI_HOST` | `0.0.0.0` | `localhost` | Web UI 绑定的 IP 地址。                                                                                                                          |
| `PASSWORD_HASH` | - | `$2y$05$Ci...` | 设置后，登录 Web UI 时需要密码。参阅 [How to generate an bcrypt hash.md]("https://github.com/xwvike/wg-easy/blob/v14/How_to_generate_an_bcrypt_hash.md") 了解如何生成该哈希。 |
| `WG_HOST` | - | `vpn.myserver.com` | VPN 服务器的公共主机名。                                                                                                              |
| `WG_DEVICE` | `eth0` | `ens6f0` | WireGuard 流量应通过的以太网设备。                                                                                   |
| `WG_PORT` | `51820` | `12345` | VPN 服务器的公共 UDP 端口。WireGuard 会在容器内监听此端口（否则使用默认值）。                                 |
| `WG_CONFIG_PORT`| `51820` | `12345` | [Home Assistant 插件](https://github.com/adriy-be/homeassistant-addons-jdeath/tree/main/wgeasy) 所使用的 UDP 端口。                                |
| `WG_MTU` | `null` | `1420` | 客户端使用的 MTU。服务器使用默认的 WG MTU。                                                                                            |
| `WG_PERSISTENT_KEEPALIVE` | `0` | `25` | 以秒为单位保持“连接”打开的值。如果为 0，则不会保持连接。                                            |
| `WG_DEFAULT_ADDRESS` | `10.8.0.x` | `10.6.0.x` | 客户端 IP 地址范围。                                                                                                                            |
| `WG_DEFAULT_DNS` | `1.1.1.1` | `8.8.8.8, 8.8.4.4` | 客户端将使用的 DNS 服务器。如果设置为空值，客户端将不使用任何 DNS。                                                                    |
| `WG_ALLOWED_IPS` | `0.0.0.0/0, ::/0` | `192.168.15.0/24, 10.0.1.0/24` | 客户端允许使用的 IP。                                                                                                                        |
| `WG_PRE_UP` | `...` | - | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L19)。                                             |
| `WG_POST_UP` | `...` | `iptables ...` | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L20)。                                             |
| `WG_PRE_DOWN` | `...` | - | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L27)。                                             |
| `WG_POST_DOWN` | `...` | `iptables ...` | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L28)。                                             |
| `LANG` | `en` | `de` | Web UI 语言（支持：en、ua、ru、tr、no、pl、fr、de、ca、es、ko、vi、nl、is、pt、zh_CN、zh_TW、it、th、hi）。                                        |
| `UI_TRAFFIC_STATS` | `false` | `true` | 在 Web UI 中启用详细的 RX / TX 客户端统计。                                                                                                       |
| `UI_CHART_TYPE` | `0` | `1` | UI_CHART_TYPE=0 # 禁用图表，UI_CHART_TYPE=1 # 折线图，UI_CHART_TYPE=2 # 面积图，UI_CHART_TYPE=3 # 柱状图。                           |

> 如果你更改了 `WG_PORT`，请确保同时更改暴露的端口。

## 更新

要更新到最新版本，只需运行：

```bash
docker stop wg-easy
docker rm wg-easy
docker pull ghcr.io/xwvike/wg-easy:14
```

然后再次运行上面的 `docker run -d \ ...` 命令。

使用 Docker Compose 可以一条命令更新 WireGuard Easy：
`docker compose up --detach --pull always`（如果在 Compose 文件中指定了镜像标签且不是 `latest`，请确保更改为所需版本；默认情况下未指定， [默认使用 `latest`](https://docs.docker.com/engine/reference/run/#image-references)）。\
如果拉取到了更新的镜像，WireGuard Easy 容器会自动重新创建。
