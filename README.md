# acme-dnsexit

使用 **DNS-01 challenge** 向 Let's Encrypt 申请证书的纯 Python 小程序，DNS 验证记录通过
**DNSExit** 的 [DNS API](https://dnsexit.com/dns/dns-api/) 自动创建和清理。

支持：

- 单域名、多域名（SAN）、通配符 `*.example.com`
- 自动探测 DNSExit 中的托管区域（zone），无需手动指定
- 申请前轮询公共 DNS 确认 TXT 已生效（支持普通 DNS 与 **DoH / DNS over HTTPS**），申请后自动删除 TXT
- 复用 account key / 证书私钥，方便续期
- Let's Encrypt 生产 / staging 环境切换
- 输出 `fullchain.pem`、`cert.pem`、`chain.pem`、`privkey.pem`

---

## 工作原理

1. 生成（或复用）ACME account key，向 Let's Encrypt 注册/查找账号；
2. 生成（或复用）域名私钥并构造 CSR，向 CA 下单；
3. 对每个待验证的授权，计算 `_acme-challenge` 所需的 TXT 值；
4. 调用 DNSExit API 添加 TXT 记录
   （同一名字下的多个值使用 `overwrite:false`，因此通配符 + 主域名可共存）；
5. 轮询公共 DNS（默认 `1.1.1.1` / `8.8.8.8`，也可用 `--doh` 走 DNS over HTTPS）
   确认记录生效；
6. 通知 CA 开始校验，轮询直到签发；
7. 写入证书文件，并在 `finally` 中删除本次添加的 TXT 记录。

> **区域（zone）自动探测**：DNSExit JSON API 没有「列出 zone」的接口，因此程序会从
> 完整记录名开始逐级向上尝试（与 acme.sh 的 `dns_dnsexit` 插件相同），API 返回
> `code:0` 的那一级即为账号下的托管区域。也可以用 `--zone` / 配置里的 `zones` 手动指定。

---

## 环境要求

- Python 3.8+
- 依赖（Debian/Ubuntu 也可直接用系统包 `python3-acme`、`python3-josepy`、
  `python3-cryptography`、`python3-dnspython`、`python3-requests`）：

```bash
pip install -r requirements.txt
```

## 获取 DNSExit API Key

登录 DNSExit → 左侧 **Settings** → **DNS API Key** → 创建，复制得到的 Key。

---

## 快速开始

### 1. 先跑 staging（不消耗生产配额，证书不被信任）

```bash
export DNSEXIT_API_KEY="你的-DNSExit-API-Key"

python3 acme_dnsexit.py \
    --staging \
    --email you@example.com \
    --domain example.com --domain '*.example.com' \
    --output-dir ./certs/example.com \
    -v
```

### 2. 确认无误后申请正式证书

```bash
python3 acme_dnsexit.py \
    --email you@example.com \
    --domain example.com --domain '*.example.com' \
    --output-dir ./certs/example.com
```

> 续期时重复执行同一条命令即可：account key 与证书私钥会从输出目录复用，
> 证书文件会被新证书覆盖。

---

## 使用配置文件

复制并修改 `config.example.json`：

```bash
cp config.example.json config.json
$EDITOR config.json
python3 acme_dnsexit.py --config config.json
```

`config.json` 字段说明：

| 字段 | 说明 | 默认 |
| --- | --- | --- |
| `api_key` | DNSExit API Key（也可用环境变量 `DNSEXIT_API_KEY`） | 必填 |
| `email` | ACME 联系邮箱（也可用环境变量 `ACME_EMAIL`） | 必填 |
| `domains` | 域名列表，支持 `*.example.com` | 必填 |
| `directory_url` | ACME 目录地址 | LE 生产 |
| `output_dir` | 证书输出目录 | `./certs` |
| `account_key` | account key 路径 | `<output_dir>/account.key` |
| `cert_key` | 证书私钥路径 | `<output_dir>/privkey.pem` |
| `key_type` | `ecdsa` 或 `rsa` | `ecdsa` |
| `elliptic_curve` | `secp256r1`/`secp384r1`/`secp521r1` | `secp256r1` |
| `rsa_key_size` | RSA 位数（`key_type=rsa` 时） | `2048` |
| `ttl` | TXT 记录 TTL（**分钟**） | `1` |
| `propagation_timeout` | 等待 DNS 生效的总秒数 | `300` |
| `propagation_interval` | 每次检查间隔秒数 | `10` |
| `dns_resolvers` | 用于检查生效的解析器列表，可混合普通 IP 与 DoH URL | `["1.1.1.1","8.8.8.8"]` |
| `doh` | 是否使用 DNS over HTTPS 检查生效 | `false` |
| `doh_resolvers` | DoH 端点列表（`doh=true` 时生效，默认 Cloudflare + Google） | `[]` |
| `skip_propagation_check` | 跳过生效检查（不推荐） | `false` |
| `finalize_timeout` | 等待 CA 校验/签发的秒数 | `120` |
| `no_cleanup` | 保留 TXT 记录（排障用） | `false` |
| `http_timeout` | 调用 DNSExit API 的超时秒数 | `30` |
| `zones` | 域名后缀 → DNSExit 托管区域 的映射 | `{}` |

命令行参数优先级高于配置文件，配置文件高于内置默认值，环境变量用于填充
`api_key` / `email`。

### `zones` 手动指定区域

当自动探测不符合预期（例如账号下同名子区域），可显式指定：

```json
{
  "zones": {
    "sub.example.com": "sub.example.com",
    "example.com": "example.com"
  }
}
```

键是证书域名所归属的后缀，值是 DNSExit 中真正的托管区域。记录名会自动按
该区域计算相对名。命令行 `--zone example.com` 相当于给所有域名加一个兜底映射。

---

## 使用 DNS over HTTPS (DoH)

若本机 UDP/TCP 53 端口被劫持或封锁，可改用 DoH 检查 TXT 是否生效：

```bash
# 使用内置 DoH 端点（Cloudflare + Google）
python3 acme_dnsexit.py --config config.json --doh

# 自定义 DoH 端点（可重复或逗号分隔）
python3 acme_dnsexit.py --config config.json \
    --doh-url https://dns.quad9.net/dns-query,https://dns.google/dns-query

# 普通 DNS 与 DoH 混用：任一解析器看到记录即视为生效
python3 acme_dnsexit.py --config config.json \
    --dns-resolvers 1.1.1.1,https://dns.google/dns-query
```

配置文件方式：

```json
{
  "doh": true,
  "doh_resolvers": [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query"
  ]
}
```

说明：

- DoH 采用标准 [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484) 线格式（`application/dns-message`），
  使用 GET 请求，通用性更好；
- 条目以 `http://` / `https://` 开头的会被当作 DoH 端点，其余当作普通 DNS 服务器；
- 检查生效时取所有解析器结果的并集，**任意一个**看到目标 TXT 值即通过，单个 DoH
  端点失败不会中断等待；
- `--doh` 默认用 Cloudflare + Google；同时也支持二者混用。

---

## 常用命令行参数

```text
--api-key / DNSEXIT_API_KEY    DNSExit API Key
--email / ACME_EMAIL           ACME 联系邮箱
--domain                       域名，可重复；支持通配符
--zone                         全局 zone 兜底
--staging / --production       环境切换
--directory                    自定义 ACME 目录 URL
--output-dir                   输出目录
--account-key / --cert-key     自定义密钥路径
--key-type / --rsa-key-size / --elliptic-curve
--ttl                           TXT TTL（分钟）
--propagation-timeout / --propagation-interval
--dns-resolvers                解析器，可重复或用逗号分隔（可填 IP 或 DoH URL）
--doh                          使用 DNS over HTTPS 检查生效（默认 Cloudflare+Google）
--doh-url                      自定义 DoH 端点，可重复/逗号分隔（隐含 --doh）
--skip-propagation-check
--finalize-timeout
--no-cleanup
--http-timeout
-v / -q                        详细 / 安静日志
```

完整列表见 `python3 acme_dnsexit.py --help`。

---

## 输出文件

```
<output_dir>/
├── account.key     # ACME 账号私钥（请妥善保管，续期需复用）
├── privkey.pem     # 证书私钥（0600 权限）
├── cert.pem        # 叶子证书
├── chain.pem       # 中间 CA 链
└── fullchain.pem   # cert.pem + chain.pem
```

Nginx 常用 `fullchain.pem` + `privkey.pem`；Apache 可用 `cert.pem` + `chain.pem`。

---

## 定时自动续期

Let's Encrypt 证书有效期 90 天，建议每天检查一次、剩余不足 30 天时续期。
ACME 客户端没有内置「到期才续」逻辑，可用一个小脚本判断：

```bash
#!/usr/bin/env bash
# /usr/local/bin/renew-dnsexit.sh
set -euo pipefail
cd /opt/acme-dnsexit
export DNSEXIT_API_KEY="你的-Key"

CERT=./certs/example.com/cert.pem
# 剩余有效期小于 30 天则续期
if ! openssl x509 -checkend $((30*24*3600)) -noout -in "$CERT" 2>/dev/null; then
    python3 acme_dnsexit.py --config config.json
    # 重新加载 Web 服务器（按需修改）
    systemctl reload nginx
fi
```

crontab（每天 03:17 检查）：

```cron
17 3 * * * /usr/local/bin/renew-dnsexit.sh >> /var/log/acme-dnsexit.log 2>&1
```

---

## 常见问题

**Q：报错 `Could not add TXT record ...: ...`？**
- 检查 API Key 是否正确、账号下确实托管了该域名。
- 若域名所在区域不是自动探测到的那一级，用 `--zone` 或 `zones` 指定。

**Q：一直等待 DNS 生效直到超时？**
- DNSExit 的 TXT 记录可能需要几分钟才对外可见，可适当调大 `propagation_timeout`。
- 本机 UDP/TCP 53 可能被封锁或劫持，试试 `--doh`（或把 DoH URL 填进 `--dns-resolvers`）。
- 可换用 `--dns-resolvers` 指定其它解析器；若排障可临时 `--no-cleanup -v` 保留记录并观察。

**Q：通配符和主域名一起申请会冲突吗？**
- 不会。两者的 `_acme-challenge.example.com` TXT 值不同，程序用 `overwrite:false`
  让两条记录共存，并分别校验后再一起提交。

**Q：staging 证书浏览器不信任？**
- 正常，staging 仅用于测试流程。去掉 `--staging` 申请生产证书。

**Q：`account.key` 丢失了怎么办？**
- 重新生成即可（会创建新的 ACME 账号），不影响签发；已签发的证书不受影响。

---

## 安全提示

- `account.key`、`privkey.pem`、`api_key` 属于敏感信息，请注意文件权限，不要提交到仓库。
- 仓库中的 `.gitignore` 已默认忽略 `config.json`、`*.key`、`*.pem`、`certs/`。

## 测试

```bash
python3 tests/test_offline.py
# 或
python3 -m unittest discover -s tests -v
```

测试完全离线（ACME 与 DNSExit 均使用 fake），不会产生任何真实请求。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `acme_dnsexit.py` | 主程序（ACME + 命令行） |
| `dnsexit.py` | DNSExit API 客户端（区域探测、增删 TXT） |
| `config.example.json` | 配置示例 |
| `requirements.txt` | 依赖 |
| `tests/test_offline.py` | 离线单元/集成测试 |
