"""Per-host token buckets, retry with backoff, SQLite response cache."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import settings


class FeedError(RuntimeError):
    """A feed failed in a way the caller should surface rather than crash on."""

    def __init__(self, source: str, message: str, status: int | None = None):
        self.source = source
        self.status = status
        super().__init__(f"[{source}] {message}")


class TokenBucket:
    """Simple async token bucket. One per upstream host."""

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.capacity = max(1, burst)
        self._tokens = float(self.capacity)
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._updated) * self.rate
                )
                self._updated = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                await asyncio.sleep((1 - self._tokens) / self.rate)


def _default_buckets() -> dict[str, TokenBucket]:
    cfg = settings()
    nvd_rate = 50 / 30 if cfg.nvd_api_key else 5 / 30
    return {
        "services.nvd.nist.gov": TokenBucket(nvd_rate, burst=2 if not cfg.nvd_api_key else 8),
        "api.first.org": TokenBucket(5, burst=10),
        "api.github.com": TokenBucket(1.0 if cfg.github_token else 0.2, burst=5),
        "api.osv.dev": TokenBucket(10, burst=20),
        "cveawg.mitre.org": TokenBucket(5, burst=10),
        "www.cisa.gov": TokenBucket(2, burst=4),
    }


_buckets: dict[str, TokenBucket] | None = None
_bucket_lock = asyncio.Lock()


async def _bucket_for(host: str) -> TokenBucket:
    global _buckets
    async with _bucket_lock:
        if _buckets is None:
            _buckets = _default_buckets()
        if host not in _buckets:
            _buckets[host] = TokenBucket(5, burst=10)
        return _buckets[host]


class ResponseCache:
    def __init__(self, path):
        self.path = path
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS cache ("
                " key TEXT PRIMARY KEY, body TEXT NOT NULL, expires REAL NOT NULL)"
            )
            self._conn.commit()
        return self._conn

    async def get(self, key: str) -> Any | None:
        async with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT body, expires FROM cache WHERE key = ?", (key,)
            ).fetchone()
            if not row:
                return None
            body, expires = row
            if expires < time.time():
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()
                return None
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return None

    async def set(self, key: str, value: Any, ttl: float) -> None:
        async with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, body, expires) VALUES (?, ?, ?)",
                (key, json.dumps(value), time.time() + ttl),
            )
            conn.commit()

    async def purge(self) -> int:
        async with self._lock:
            conn = self._connect()
            cur = conn.execute("DELETE FROM cache")
            conn.commit()
            return cur.rowcount


_cache: ResponseCache | None = None


def cache() -> ResponseCache:
    global _cache
    if _cache is None:
        _cache = ResponseCache(settings().state_dir / "feed-cache.sqlite3")
    return _cache


@dataclass
class Client:
    _client: httpx.AsyncClient | None = None

    async def _ensure(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            cfg = settings()
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(cfg.timeout),
                headers={"User-Agent": cfg.user_agent, "Accept": "application/json"},
                follow_redirects=True,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def request_json(
        self,
        method: str,
        url: str,
        *,
        source: str,
        params: Mapping[str, Any] | None = None,
        json_body: Any | None = None,
        headers: Mapping[str, str] | None = None,
        ttl: float = 3600,
        ok_statuses: tuple[int, ...] = (200,),
        empty_on: tuple[int, ...] = (404,),
    ) -> Any:
        cfg = settings()
        cache_key = _cache_key(method, url, params, json_body)

        if cfg.cache_enabled:
            hit = await cache().get(cache_key)
            if hit is not None:
                return hit

        if cfg.offline:
            raise FeedError(source, "offline mode is on and this request was not cached")

        host = urlparse(url).netloc
        bucket = await _bucket_for(host)
        client = await self._ensure()

        last_error = "unknown error"
        for attempt in range(cfg.max_retries + 1):
            await bucket.acquire()
            try:
                resp = await client.request(
                    method, url, params=params, json=json_body, headers=dict(headers or {})
                )
            except httpx.HTTPError as exc:
                last_error = f"transport error: {exc}"
                await asyncio.sleep(min(2**attempt, 8))
                continue

            if resp.status_code in empty_on:
                payload: Any = None
                if cfg.cache_enabled:
                    await cache().set(cache_key, payload, min(ttl, 900))
                return payload

            if resp.status_code in ok_statuses:
                try:
                    payload = resp.json()
                except ValueError as exc:
                    raise FeedError(source, "upstream returned non-JSON body", resp.status_code) from exc
                if cfg.cache_enabled:
                    await cache().set(cache_key, payload, ttl)
                return payload

            if resp.status_code in (429, 500, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if (retry_after or "").isdigit() else min(2**attempt, 10)
                last_error = f"HTTP {resp.status_code}, retrying in {delay:.0f}s"
                await asyncio.sleep(delay)
                continue

            raise FeedError(source, f"HTTP {resp.status_code}: {resp.text[:200]}", resp.status_code)

        raise FeedError(source, f"gave up after {cfg.max_retries + 1} attempts ({last_error})")

    async def get_json(self, url: str, **kw) -> Any:
        return await self.request_json("GET", url, **kw)

    async def post_json(self, url: str, **kw) -> Any:
        return await self.request_json("POST", url, **kw)


def _cache_key(method: str, url: str, params, body) -> str:
    blob = json.dumps(
        [method, url, sorted((params or {}).items()), body], sort_keys=True, default=str
    )
    return hashlib.sha256(blob.encode()).hexdigest()


_shared: Client | None = None


def client() -> Client:
    global _shared
    if _shared is None:
        _shared = Client()
    return _shared


async def aclose() -> None:
    if _shared is not None:
        await _shared.aclose()
