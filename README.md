# 1. 工具用途（安全领域作用）

这个脚本本质上是一个 **Webshell 自动化检测与风险扫描工具**，用于在大量 URL 路径中识别可能存在的 Webshell（网页后门）。

# 🧠 本质定位（优化版）

👉 **基于 asyncio + aiohttp 的高并发 Webshell 资产扫描与风险识别引擎**

该工具属于 **大规模 URL 安全探测类扫描器**，核心目标是：

在高并发 HTTP 请求下，对 Web 目录资产进行快速风险识别与 Webshell 检测。

## ⚙️ 架构类型对比

| 版本           | 技术栈                | 并发能力     | 稳定性     | 适用场景         |
| ------------ | ------------------ | -------- | ------- | ------------ |
| requests版    | sync + thread pool | 中低       | 高       | 小规模资产 / 稳定扫描 |
| asyncio版（当前） | asyncio + aiohttp  | 高（数千级并发） | 中高（需调参） | 大规模资产 / 红队扫描 |


### 核心用途：

* 扫描大量 `目录 × 文件字典` 组合 URL
* 检测是否存在：

  * PHP Webshell（如 `WSO`, `b374k`, `c99`）
  * 危险函数（`eval`, `system`, `exec` 等）
  * 文件管理 / 上传 UI 特征
* 输出高风险目标 URL
* 自动评分（0–100）+ 风险等级（LOW / MEDIUM / HIGH / CRITICAL）

👉 典型安全场景：

* 红队渗透测试（资产后渗透验证）
* 蓝队 Webshell 扫描与应急响应
* 批量站点安全巡检
* Bug bounty 自动化辅助工具



# 2. 工作流程（输入 → 输出）

## 整体流程：
```
目录文件 + 字典文件
        ↓
生成 URL 队列 (directory × filename)
        ↓
async producer 写入 queue
        ↓
worker 并发消费 queue
        ↓
HEAD 预检（过滤无效请求）
        ↓
GET 请求获取页面
        ↓
内容分析（规则 + 正则 + fingerprint）
        ↓
风险评分系统
        ↓
命中则写入结果文件 + 打印日志
```


## 请求处理流程：

1. HEAD 请求预检查（减少流量）
2. 判断 Content-Type
3. GET 请求获取内容
4. 读取最大 2MB 响应
5. WAF / 错误页过滤
6. 提取 `<title>`
7. 规则引擎评分
8. 输出结果


# 3. 关键模块解析

## 3.1 扫描模块（Producer / Worker）

### Producer：

* 生成 `(directory, filename)` 组合
* 放入 asyncio.Queue

### Worker：

* 多协程消费任务
* 调用 `check_url()`


## 3.2 请求模块（aiohttp）

使用：

* `aiohttp.ClientSession`
* TCP 连接池（limit=600）
* 超时控制（22s total）

特点：

* 高并发 HTTP 扫描
* keepalive 复用连接
* SSL 校验关闭（用于渗透场景）


## 3.3 过滤模块（减少误报）

### HEAD 预检：

* 避免无效 GET
* 过滤大文件

### WAF 检测：

```python
cloudflare / captcha / access denied
```

### 错误页识别：

* MD5 hash 统计
* 同一 host 重复错误页过滤


## 3.4 规则引擎（核心）

### ① 高危 fingerprint（最高优先级）

```python
wso, b374k, c99, r57 ...
```

👉 命中直接：

```
score = 100, CRITICAL
```


### ② 危险函数检测（regex）

检测：

* system()
* exec()
* passthru()
* eval()
* base64_decode()
* gzinflate()


### ③ UI 特征识别

判断 Webshell 管理面板：

* `<textarea>` + cmd/system
* upload file / file manager

---

### ④ PHP上下文增强

```python
<?php + 多危险函数 => score × 1.6
```


## 3.5 自适应并发系统（重点）

动态调整：

| 条件        | 行为   |
| --------- | ---- |
| 429 > 8%  | 降低并发 |
| 403 > 15% | 降低并发 |
| 200 > 75% | 提高并发 |

机制：

* asyncio.Semaphore 动态重建
* 每 8 秒调整一次
* stats 自动清空


## 3.6 评分系统

```text
0 - 54   LOW
55 - 59  MEDIUM
60 - 79  HIGH
80 - 100 CRITICAL
```

评分逻辑：

* fingerprint：直接 100
* regex：每个 +30
* UI 特征：+22
* PHP context：+12
* 多函数组合加权（乘数）


# 4. 命令行参数说明（argparse）

| 参数                   | 说明            |
| -------------------- | ------------- |
| `-d / --directories` | 目录列表文件        |
| `-w / --dictionary`  | 文件字典          |
| `-o / --output`      | 输出结果文件        |
| `--min-score`        | 最低命中分数（默认 55） |
| `-c / --concurrency` | worker 并发数    |
| `--global-limit`     | 全局并发限制        |
| `--user-agent`       | 请求 UA         |
| `--allow-redirect`   | 是否允许重定向       |

---

# 5. 输入 / 输出示例

## 输入：

### directories.txt

```
/admin
/upload
/shell
```

### dictionary.txt

```
shell.php
cmd.php
upload.php
```


## 实际扫描 URL：

```
/admin/shell.php
/admin/cmd.php
/upload/shell.php
...
```


## 输出：

```
http://target.com/admin/shell.php|score=92|risk=CRITICAL|title=WSO 2.5 Shell
```


# 6. 并发与性能机制

## 6.1 异步架构（核心）

* asyncio + aiohttp
* queue 控制任务流


## 6.2 并发模型

```
Producer → Queue → Workers(N)
```


## 6.3 限流机制

* 全局 semaphore（global_limit）
* host 级 semaphore（防单域过载）


## 6.4 HTTP 优化

* TCP 连接池（600）
* keep-alive
* DNS cache
* HEAD precheck

## 6.5 自适应控制

动态调整并发（核心性能优化点）：

* 避免触发 WAF
* 自动降低攻击强度
* 自动恢复性能


# 7. 风险提示（非常重要）

## 7.1 误报风险（False Positive）

可能误判：

* CMS 管理页面（含 upload UI）
* 正常 PHP debug 页面
* base64/gzinflate 压缩内容
* 开发测试接口

---

## 7.2 漏报风险（False Negative）

* Webshell 加密/混淆
* Java / ASP / JSP 后门
* 无 PHP 特征 shell


## 7.3 滥用风险（Dual-use）

⚠️ 该工具可被用于：

* 未授权扫描网站
* 批量漏洞探测
* 资产攻击面枚举

👉 在很多司法辖区可能违法


## 7.4 性能风险

* queue 最大 12000（内存压力）
* 超高并发可能触发封 IP
* aiohttp session 未限严格 rate control


# 8. 如何部署和使用（步骤）

## 8.1 环境安装

```bash
git clone https://github.com/Michael-TopKing/Webshell-Checker-V2.git
cd Webshell-Checker-V2
pip3 install -r requirements.txt
```


## 8.2 准备文件

### 目录列表

```
directories.txt
```

### 文件字典

```
dict.txt
```


## 8.3 运行工具

```bash
python3 detector.py \
  -d directories.txt \
  -w dict.txt \
  -o result.txt \
  -c 150 \
  --global-limit 220 \
  --min-score 55
```

---

## 8.4 输出查看

```bash
cat result.txt
```


## 8.5 日志

```
webshell_detector.log
```

记录：

* 并发调整
* 状态码统计
* worker error


