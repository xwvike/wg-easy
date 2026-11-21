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
* 在界面上直接编辑每个客户端的 AllowedIPs。
* 展示客户端的二维码。
* 下载或复制客户端配置。
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
  -p 127.0.0.1:51821:51821/tcp \
  --cap-add=NET_ADMIN \
  --sysctl="net.ipv4.conf.all.src_valid_mark=0" \
  --sysctl="net.ipv4.ip_forward=1" \
  --restart unless-stopped \
  ghcr.io/xwvike/wg-easy
```

> 💡 将 `YOUR_SERVER_IP` 替换为你的 WAN IP，或动态 DNS 主机名。
>
> 💡 `PASSWORD_HASH` **必填**——未设置时容器会拒绝启动。将 `YOUR_ADMIN_PASSWORD_HASH` 替换为 bcrypt 哈希。参阅 [How_to_generate_an_bcrypt_hash.zh.md](./How_to_generate_an_bcrypt_hash.zh.md)。

Web UI 将可通过 `http://127.0.0.1:51821` 访问。

> 💡 你的配置文件会保存在 `~/.wg-easy`。

WireGuard Easy 也可以通过 Docker Compose 启动 —— 直接下载
[`docker-compose.yml`](docker-compose.yml)，进行必要的调整，然后执行
`docker compose up --detach`。

本地开发可运行 `npm run serve`。开发配置使用公开的示例密码。管理页面发布在 `http://127.0.0.1:51821`，同时关闭了经 VPN 直连管理页面的入口。

生产 Compose 模板要求通过 HTTPS 签发会话 Cookie。登录前请配置 TLS 代理和可信来源地址。本机 HTTP 开发使用开发配置。

#### 升级已有部署

如果启用了 `TRUST_PROXY=true` 或 `1`，请在重启前移除它。将 `TRUSTED_PROXIES` 设为容器实际看到的反向代理来源地址，并让代理覆盖传入的转发请求头。如果通过 Cloudflare Tunnel 接入，且可信代理提供 `cf-connecting-ip`，请设置 `REAL_IP_HEADER=cf-connecting-ip`。代理运行在宿主机时，可将管理端口发布为 `127.0.0.1:51821:51821/tcp`。如果 VPN 客户端也必须经过代理访问管理页面，请设置 `WEBUI_VPN_ACCESS=false`。

IPv4 出站过滤默认开启。如果客户端原先通过 `WG_ALLOWED_IPS=0.0.0.0/0, ::/0` 访问服务器所在的内网，升级时请把实际内网段追加到列表，例如 `0.0.0.0/0, ::/0, 192.168.15.0/24`。`WG_DEFAULT_DNS` 中的私有 DNS 地址也允许 TCP 和 UDP 的 53 端口流量。即使列入允许范围，`169.254.0.0/16` 和 `100.100.100.200/32` 仍会阻止来自客户端的新建出站连接。需要沿用原来的转发行为时，可设置 `WG_EGRESS_FILTER=false`。

### 3. 赞助

喜欢这个项目吗？[请为 Emile 买杯啤酒！](https://github.com/sponsors/WeeJeWel) 🍻

## 可选项

可以在 `docker run` 命令中使用 `-e KEY="VALUE"` 设置环境变量来配置下列选项。

| 环境变量 | 默认值 | 示例 | 描述                                                                                                                                          |
| - | - | - |------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PORT` | `51821` | `6789` | Web UI 的 TCP 端口。                                                                                                                                 |
| `WEBUI_HOST` | `0.0.0.0` | `localhost` | Web UI 绑定的 IP 地址。                                                                                                                          |
| `PASSWORD_HASH` | - | `$2y$05$Ci...` | **必填。** Web UI / API 登录用的 bcrypt 密码哈希；未设置时进程拒绝启动。参阅 [How_to_generate_an_bcrypt_hash.zh.md](./How_to_generate_an_bcrypt_hash.zh.md)。 |
| `SESSION_SECRET` | 随机 | `long-random-string` | 用于签名会话 Cookie。会话保存在内存中，重启后需要重新登录。 |
| `SESSION_MAX_AGE` | `43200000` | `86400000` | 会话有效期（毫秒，默认 12 小时）。 |
| `SECURE_COOKIE` | `auto` | `true` | Cookie `Secure`：`true`、`false` 或 `auto`（HTTPS 请求时自动开启）。 |
| `TRUSTED_PROXIES` | 空 | `172.18.0.2` | 允许提供转发请求头的代理 IP 或 CIDR，多个地址用逗号分隔。 |
| `REAL_IP_HEADER` | `x-forwarded-for` | `cf-connecting-ip` | 可信代理用来传递客户端 IP 的请求头。 |
| `WEBUI_VPN_ACCESS` | `true` | `false` | 允许 VPN 客户端直接访问 Web UI 和 API。 |
| `LOGIN_GLOBAL_MAX_ATTEMPTS` | `100` | `50` | 每个时间窗口共享的登录额度。额度用尽时，只有曾登录成功的客户端地址可以继续尝试。 |
| `LOGIN_MAX_ATTEMPTS` | `5` | `10` | 登录 / `Authorization` 失败次数上限，超出后临时锁定。 |
| `LOGIN_WINDOW_MS` | `900000` | `600000` | 统计失败次数的滑动窗口（毫秒）。 |
| `LOGIN_LOCKOUT_MS` | `900000` | `1800000` | 锁定时长（毫秒）。 |
| `WG_HOST` | - | `vpn.myserver.com` | VPN 服务器的公共主机名。                                                                                                              |
| `WG_DEVICE` | `eth0` | `ens6f0` | WireGuard 流量应通过的以太网设备。                                                                                   |
| `WG_PORT` | `51820` | `12345` | VPN 服务器的公共 UDP 端口。WireGuard 会在容器内监听此端口（否则使用默认值）。                                 |
| `WG_CONFIG_PORT`| `51820` | `12345` | [Home Assistant 插件](https://github.com/adriy-be/homeassistant-addons-jdeath/tree/main/wgeasy) 所使用的 UDP 端口。                                |
| `WG_MTU` | `null` | `1420` | 客户端使用的 MTU。服务器使用默认的 WG MTU。                                                                                            |
| `WG_PERSISTENT_KEEPALIVE` | `0` | `25` | 以秒为单位保持“连接”打开的值。如果为 0，则不会保持连接。                                            |
| `WG_DEFAULT_ADDRESS` | `10.8.0.x` | `10.6.0.x` | 客户端 IP 地址范围。                                                                                                                            |
| `WG_DEFAULT_DNS` | `1.1.1.1` | `8.8.8.8, 8.8.4.4` | 客户端将使用的 DNS 服务器。如果设置为空值，客户端将不使用任何 DNS。                                                                    |
| `WG_ALLOWED_IPS` | `0.0.0.0/0, ::/0` | `192.168.15.0/24, 10.0.1.0/24` | 客户端允许使用的 IP。                                                                                                                        |
| `WG_EGRESS_FILTER` | `true` | `false` | 按 `WG_ALLOWED_IPS` 过滤从 VPN 客户端转发到隧道外的 IPv4 流量。 |
| `WG_PRE_UP` | `...` | - | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L19)。                                             |
| `WG_POST_UP` | `...` | `iptables ...` | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L20)。                                             |
| `WG_PRE_DOWN` | `...` | - | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L27)。                                             |
| `WG_POST_DOWN` | `...` | `iptables ...` | 默认值参见 [config.js](https://github.com/wg-easy/wg-easy/blob/master/src/config.js#L28)。                                             |
| `LANG` | `en` | `de` | Web UI 语言（支持：en、ua、ru、tr、no、pl、fr、de、ca、es、ko、vi、nl、is、pt、zh_CN、zh_TW、it、th、hi）。                                        |
| `UI_GRAVATAR` | `false` | `true` | 从 Gravatar 加载头像，会向其发送客户端名称的哈希值。 |
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
