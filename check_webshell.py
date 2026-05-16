#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import logging
import random
import re
import time
from collections import defaultdict, deque, Counter
from pathlib import Path
from typing import List
from urllib.parse import urlparse
import aiohttp

# ====================== 配置 ======================
CRITICAL_FINGERPRINTS = {"wso", "filesman", "b374k", "c99", "r57", "sym", "indoxploit", "madspot", "priv8"}

CRITICAL_REGEX = [
    r"system\s*\(", r"exec\s*\(", r"passthru\s*\(", r"shell_exec\s*\(",
    r"eval\s*\(", r"assert\s*\(", r"base64_decode\s*\(", r"gzinflate\s*\(",
]

ALLOWED_CONTENT_TYPES = {'text/html', 'text/plain', 'application/xhtml+xml'}

MAX_RESPONSE_SIZE = 2_000_000
MAX_HASHES_PER_HOST = 120

class WebshellDetector:
    def __init__(self, args):
        self.args = args
        self.setup_logging()
        self.session = None
        
        self.global_semaphore = asyncio.Semaphore(args.global_limit)
        self.host_semaphores = defaultdict(lambda: asyncio.Semaphore(4))
        
        self.error_page_hashes = defaultdict(lambda: deque(maxlen=MAX_HASHES_PER_HOST))
        self.compiled_regex = [re.compile(p, re.IGNORECASE) for p in CRITICAL_REGEX]
        self.title_re = re.compile(r'<title>(.*?)</title>', re.I | re.S)
        self.result_file = None

        # Adaptive Concurrency 相关
        self.stats = Counter()                    # 200, 429, 403, timeout 等
        self.last_adjust_time = time.time()
        self.current_global_limit = args.global_limit

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            handlers=[logging.FileHandler('webshell_detector.log', encoding='utf-8')]
        )
        self.logger = logging.getLogger(__name__)

    async def init_session(self):
        connector = aiohttp.TCPConnector(limit=600, ttl_dns_cache=300, keepalive_timeout=35, ssl=False)
        timeout = aiohttp.ClientTimeout(total=22, connect=12, sock_read=18)

        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': self.args.user_agent},
            connector=connector
        )
        self.result_file = open(self.args.output, 'w', encoding='utf-8')

    def safe_url(self, base: str, filename: str) -> str:
        return f"{base.rstrip('/')}/{filename.lstrip('/')}"

    async def head_precheck(self, url: str) -> bool:
        """HEAD 预检 + Fallback 逻辑"""
        try:
            async with self.session.head(url, allow_redirects=self.args.allow_redirect, timeout=10) as resp:
                if resp.status == 200:
                    content_type = resp.headers.get('Content-Type', '').lower()
                    if any(allowed in content_type for allowed in ALLOWED_CONTENT_TYPES):
                        if resp.content_length and resp.content_length > MAX_RESPONSE_SIZE * 2:
                            return False
                        return True
                # HEAD 返回非200 或 不可信内容类型 → 直接 fallback 到 GET
                return None  # None 表示需要 fallback GET
                
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None   # 任何异常都 fallback 到 GET

    async def check_url(self, base_url: str, filename: str):
        full_url = self.safe_url(base_url, filename)
        host = urlparse(full_url).netloc

        async with self.global_semaphore, self.host_semaphores[host]:
            # === HEAD Precheck + Fallback ===
            head_result = await self.head_precheck(full_url)
            if head_result is False:
                self.stats['head_rejected'] += 1
                return
            # head_result is None → 需要执行 GET

            for attempt in range(3):
                try:
                    async with self.session.get(full_url, allow_redirects=self.args.allow_redirect) as resp:
                        self.stats[resp.status] += 1

                        content_type = resp.headers.get('Content-Type', '').lower()
                        if not any(allowed in content_type for allowed in ALLOWED_CONTENT_TYPES):
                            return

                        body = await resp.content.read(MAX_RESPONSE_SIZE + 8192)
                        if len(body) > MAX_RESPONSE_SIZE:
                            return
                        content = body.decode('utf-8', errors='ignore')

                        if resp.status != 200:
                            self._adaptive_adjust()
                            return
                        if self.is_waf_or_blocked(resp.status, content):
                            return
                        if self.is_likely_error_page(host, content):
                            return

                        title_match = self.title_re.search(content)
                        title = title_match.group(1).strip() if title_match else ""

                        score, risk, matched = self.calculate_risk(content, title)

                        if score >= self.args.min_score and len(matched) >= 2:
                            line = f"{full_url}|score={score}|risk={risk}|title={title[:100]}\n"
                            self.result_file.write(line)
                            self.result_file.flush()

                            color = "\033[1;32m" if score >= 75 else "\033[1;33m"
                            print(f"{color}🚨 [{risk}] {score} → {full_url}\033[0m")
                            self.logger.info(f"[{risk}] {score} | {full_url}")

                    self._adaptive_adjust()
                    break

                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    self.stats['timeout'] += 1
                    self._adaptive_adjust()
                    if attempt < 2:
                        await asyncio.sleep(1.5 ** attempt + random.uniform(0.3, 1.3))
                    continue
                except Exception:
                    break

    def _adaptive_adjust(self):
        """自适应并发调整"""
        now = time.time()
        if now - self.last_adjust_time < 8:   # 每8秒最多调整一次
            return

        total = sum(self.stats.values())
        if total < 300:
            return

        rate_429 = self.stats[429] / total
        rate_403 = self.stats[403] / total
        rate_200 = self.stats[200] / total

        old_limit = self.current_global_limit

        if rate_429 > 0.08 or rate_403 > 0.15:
            self.current_global_limit = max(30, self.current_global_limit - 25)
            self.global_semaphore = asyncio.Semaphore(self.current_global_limit)
            self.logger.warning(f"↓ Adaptive down to {self.current_global_limit} (429/403 too high)")
        elif rate_200 > 0.75 and self.current_global_limit < self.args.global_limit:
            self.current_global_limit = min(self.args.global_limit, self.current_global_limit + 20)
            self.global_semaphore = asyncio.Semaphore(self.current_global_limit)
            self.logger.info(f"↑ Adaptive up to {self.current_global_limit}")

        self.last_adjust_time = now
        self.stats.clear()   # 重置统计

    def is_waf_or_blocked(self, status: int, content: str) -> bool:
        if status != 200:
            return True
        text = content.lower()[:1500]
        signs = ["cloudflare", "cf-ray", "captcha", "sucuri", "attention required", "access denied"]
        return any(sign in text for sign in signs)

    def is_likely_error_page(self, host: str, content: str) -> bool:
        if len(content) < 400:
            return True
        short_hash = hashlib.md5(content[:2800].encode()).hexdigest()
        self.error_page_hashes[host].append(short_hash)
        return self.error_page_hashes[host].count(short_hash) >= 4

    def calculate_risk(self, content: str, title: str):
        text_lower = content.lower()
        title_lower = title.lower() if title else ""
        score = 0
        matched = []
        critical_count = 0

        # Fingerprint 最高优先级
        for fp in CRITICAL_FINGERPRINTS:
            if fp in text_lower or fp in title_lower:
                return 100, "CRITICAL", [f"FINGERPRINT:{fp}"]

        # 危险函数
        php_context = bool(re.search(r'<\?php|<\?', content[:800]))
        regex_matches = []
        for pattern in self.compiled_regex:
            if pattern.search(content):
                critical_count += 1
                regex_matches.append(pattern.pattern[:15])

        score += critical_count * 30
        if critical_count >= 1:
            matched.append(f"REGEX×{critical_count}")

        # === 交互加成（最重要优化）===
        if critical_count >= 2:
            score += 25                      # 多函数基础加成
        if critical_count >= 3:
            score += 20
        if php_context and critical_count >= 2:
            score *= 1.6                     # 强乘数
            matched.append("PHP_MULTI×1.6")

        # UI 特征
        if "<textarea" in text_lower and any(k in text_lower for k in ["cmd", "exec", "shell", "system"]):
            score += 22
            matched.append("TEXTAREA_CMD")
        if any(x in text_lower for x in ['type="file"', 'upload file', 'file manager', 'uploader']):
            score += 22
            matched.append("UPLOAD_UI")

        if php_context:
            score += 12

        final_score = min(int(score), 100)
        risk = "CRITICAL" if final_score >= 80 else "HIGH" if final_score >= 60 else "MEDIUM" if final_score >= self.args.min_score else "LOW"
        return final_score, risk, matched

    # producer / worker / run 方法保持不变（与 v6.4 一致）
    async def producer(self, queue: asyncio.Queue, directories: List[str], filenames: List[str]):
        for d in directories:
            for f in filenames:
                await queue.put((d, f))

    async def worker(self, queue: asyncio.Queue):
        while True:
            item = None
            try:
                item = await queue.get()
                await self.check_url(*item)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.debug(f"Worker error: {type(e).__name__}")
            finally:
                if item is not None:
                    queue.task_done()

    async def run(self):
        await self.init_session()
        try:
            directories = self.load_file(self.args.directories)
            filenames = self.load_file(self.args.dictionary)

            random.shuffle(directories)
            random.shuffle(filenames)

            queue: asyncio.Queue = asyncio.Queue(maxsize=12000)

            total = len(directories) * len(filenames)
            self.logger.info(f"Scan started → {total:,} targets | Global: {self.args.global_limit} | Adaptive Enabled")

            workers = [asyncio.create_task(self.worker(queue)) for _ in range(self.args.concurrency)]
            producer = asyncio.create_task(self.producer(queue, directories, filenames))

            await producer
            await queue.join()

            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

            self.logger.info(f"Scan completed. Results saved to {self.args.output}")

        finally:
            if self.result_file:
                self.result_file.close()
            if self.session:
                await self.session.close()

    def load_file(self, filepath: str) -> List[str]:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]


def main():
    parser = argparse.ArgumentParser(description="Webshell Detector v6.5 - Smart Scoring + Adaptive")
    parser.add_argument('--directories', '-d', required=True)
    parser.add_argument('--dictionary', '-w', required=True)
    parser.add_argument('--output', '-o', default='found_webshells.txt')
    parser.add_argument('--min-score', type=int, default=55)
    parser.add_argument('--concurrency', '-c', type=int, default=150)
    parser.add_argument('--global-limit', type=int, default=220, help='Initial global concurrency')
    parser.add_argument('--user-agent', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
    parser.add_argument('--allow-redirect', action='store_true')
    args = parser.parse_args()

    detector = WebshellDetector(args)
    asyncio.run(detector.run())


if __name__ == "__main__":
    main()
