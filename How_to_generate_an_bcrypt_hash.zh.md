# 生成 bcrypt 哈希密码

在 wg-easy v14 中，需要提供 bcrypt 哈希后的密码，而不是明文密码。本说明介绍如何根据明文密码生成哈希。

## 使用 Docker + node

- 使用 docker compose

    使用 docker 和 node 通过 wgpw 生成 bcrypt 哈希的最简单方式：

    ```sh
    docker run ghcr.io/xwvike/wg-easy node -e 'const bcrypt = require("bcryptjs"); const hash = bcrypt.hashSync("YOUR_PASSWORD", 10); console.log(hash.replace(/\$/g, "$$$$"));'
    ```

    哈希后的密码会打印在终端。复制它并填写到 docker compose 的 `PASSWORD_HASH` 环境变量。

- 使用 `docker run`

    如果通过 `docker run` 运行 wg-easy，必须用单引号（`'...'`）包裹哈希字符串。可以使用以下命令：

    ```sh
    docker run --rm ghcr.io/xwvike/wg-easy:14 node -e "const bcrypt = require('bcryptjs'); const hash = bcrypt.hashSync('YOUR_PASSWORD', 10); console.log('\'' + hash + '\'');"
    ```

    哈希后的密码会打印在终端。复制它并在 docker run 命令中用于 `PASSWORD_HASH` 环境变量。

## 使用 Docker + wgpw

`wg-password`（wgpw）是生成 bcrypt 密码哈希的脚本，可以配合 docker 使用：

```sh
docker run ghcr.io/xwvike/wg-easy wgpw YOUR_PASSWORD
```

输出类似如下：

```sh
PASSWORD_HASH='$2b$12$coPqCsPtcFO.Ab99xylBNOW4.Iu7OOA2/ZIboHN6/oyxca3MWo7fW'
```

此示例中 `$2b$12$coPqCsPtcFO.Ab99xylBNOW4.Iu7OOA2/ZIboHN6/oyxca3MWo7fW` 即为哈希密码。使用 docker-compose 时，需要将每个 `$` 前再加一个 `$` 以避免被解释为变量。最终可用于 docker-compose 的密码如下：

```sh
$$2b$$12$$coPqCsPtcFO.Ab99xylBNOW4.Iu7OOA2/ZIboHN6/oyxca3MWo7fW
```
