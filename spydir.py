#!/usr/bin/env python
# pylint: disable=C,R,W
"""Directery Listing Scanner"""
from __future__ import annotations

import argparse
import itertools
import logging
import multiprocessing as mp
import re
import sys
import threading
from dataclasses import dataclass
from typing import Sequence, TextIO, Type
from urllib.parse import urljoin

import requests

__version__ = "0.1.0"

__author__ = "Sergey M"

logger = mp.get_logger()

requests.packages.urllib3.disable_warnings()


class ANSI:
    CSI = "\x1b["
    RESET = f"{CSI}m"
    CLEAR_LINE = f"{CSI}2K\r"
    BLACK = f"{CSI}30m"
    RED = f"{CSI}31m"
    GREEN = f"{CSI}32m"
    YELLOW = f"{CSI}33m"
    BLUE = f"{CSI}34m"
    MAGENTA = f"{CSI}35m"
    CYAN = f"{CSI}36m"
    WHITE = f"{CSI}37m"
    GREY = f"{CSI}90m"
    BRIGHT_RED = f"{CSI}91m"
    BRIGHT_GREEN = f"{CSI}92m"
    BRIGHT_YELLOW = f"{CSI}99m"
    BRIGHT_BLUE = f"{CSI}94m"
    BRIGHT_MAGENTA = f"{CSI}95m"
    BRIGHT_CYAN = f"{CSI}96m"
    BRIGHT_WHITE = f"{CSI}97m"


class ColorHandler(logging.StreamHandler):
    _log_colors: dict[int, str] = {
        logging.DEBUG: ANSI.BLUE,
        logging.INFO: ANSI.GREEN,
        logging.WARNING: ANSI.YELLOW,
        logging.ERROR: ANSI.RED,
        logging.CRITICAL: ANSI.BRIGHT_RED,
    }

    _fmt = logging.Formatter(
        "[%(levelname).1s] %(processName)-16s - %(message)s"
    )

    def format(self, record: logging.LogRecord) -> str:
        message = self._fmt.format(record)
        return f"{self._log_colors[record.levelno]}{message}{ANSI.RESET}"


class Worker(mp.Process):
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"

    downloadable_exts = (
        # archives
        ".7z",
        ".rar",
        ".tar",
        ".tar.bz2",
        ".tar.gz",
        ".tar.xz",
        ".tar.zst",
        ".tgz",
        ".txz",
        ".zip",
        # dumps
        ".sql",
        ".sql.gz",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".dump",
        # ".dump.sql",
        # config
        ".conf",
        ".cfg",
        ".ini",
        ".yml",
        ".yaml",
        # php
        ".inc",
        # other
        ".bk",
        ".bak",
        ".Dockerfile",
        ".log",
        ".log.gz",
    )

    def __init__(
        self,
        in_q: mp.JoinableQueue,
        out_q: mp.Queue,
        seen: dict,
        timeout: float | None = None,
        session: requests.Session | None = None,
        user_agent: str | None = None,
    ) -> None:
        super().__init__(daemon=True)
        self.in_q = in_q
        self.out_q = out_q
        self.seen = seen
        self.timeout = timeout
        self.session = session or self.default_session()
        self.user_agent = user_agent or self.user_agent
        self.start()

    def default_session(self) -> requests.Session:
        s = requests.session()
        s.headers.update({"User-Agent": self.user_agent})
        return s

    def run(self) -> None:
        while True:
            try:
                if (url := self.in_q.get()) is None:
                    break

                if url in self.seen:
                    logger.debug("already seen: %s", url)
                    continue

                logger.debug("check directory listing: %s", url)

                response = self.session.get(
                    url,
                    allow_redirects=False,
                    verify=False,
                    timeout=self.timeout,
                )

                if response.status_code != 200:
                    logger.warning("%d - %s", response.status_code, url)
                    continue

                self.seen[url] = True
                html = response.text

                if "<title>Index of /" not in html:
                    logger.warning("directory listing not found: %s", url)
                    continue

                links = self.extract_links(html)
                self.process_links(links, url)
            except BaseException as ex:
                logger.error(ex)
            finally:
                self.in_q.task_done()

    def extract_links(self, s: str) -> list[str]:
        return re.findall('<a href="([^"]+)', s)

    def process_links(self, links: list[str], base_url: str) -> None:
        top_level_url = urljoin(base_url, "..")

        for link in links:
            # Сортировка списка файлов
            # ?C=N;O=D
            if "?" in link:
                continue

            url = urljoin(base_url, link)

            # logger.debug("found link: %s", url)

            # Не переходим на уровень выше
            if url == top_level_url:
                continue

            # Все что можно скачать
            if url.lower().endswith(self.downloadable_exts):
                logger.info("found: %s", url)
                self.out_q.put(url)
                continue

            # Проверяем все вложенные папки
            if url.endswith("/"):
                self.in_q.put(url)


def normalize_url(s: str) -> str:
    return ["https://", ""]["://" in s] + s


class OutputThread(threading.Thread):
    def __init__(self, stream: TextIO, queue: mp.Queue) -> None:
        super().__init__()
        self.stream = stream
        self.queue = queue

    def run(self) -> None:
        while True:
            url = self.queue.get()
            if url is None:
                break
            self.stream.write(f"{url}\n")
            self.stream.flush()


KNOWN_PATHES = (
    "/wordpress/wp-content/",
    "/wordpress/",
    "/backup/",
    "/backups/",
    "/dump/",
    "/dumps/",
    "/database/",
    "/db/",
    "/sql/",
    "/data/",
    "/files/",
    "/upload/",
    "/uploads/",
    "/include/",
    "/includes/",
    "/inc/",
    "/sys/",
    "/system/",
    "/lib/",
    "/.docker/",
    "/docker/",
    "/logs/",
    "/log/",
)


@dataclass
class SpyDir:
    output: TextIO
    workers_num: int
    timeout: float

    class NameSpace(argparse.Namespace):
        input: TextIO
        output: TextIO
        workers_num: int
        debug: bool
        timeout: float

    @classmethod
    def parse_args(
        cls: Type[SpyDir],
        argv: Sequence[str] | None,
    ) -> tuple[argparse.ArgumentParser, NameSpace]:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument(
            "-i", "--input", type=argparse.FileType(), default="-"
        )
        parser.add_argument(
            "-o", "--output", type=argparse.FileType("w+"), default="-"
        )
        parser.add_argument(
            "-w", "--workers-num", type=int, default=mp.cpu_count() - 1
        )
        parser.add_argument("-d", "--debug", action="store_true", default=False)
        parser.add_argument("-t", "--timeout", type=float, default=10.0)
        return parser, parser.parse_args(args=argv, namespace=cls.NameSpace())

    @classmethod
    def cli(cls: Type[SpyDir], argv: Sequence[str] | None = None) -> None:
        parser, args = cls.parse_args(argv)

        cls.configure_logger(args)

        obj = cls(
            output=args.output,
            workers_num=args.workers_num,
            timeout=args.timeout,
        )

        sites = map(normalize_url, filter(None, args.input))

        try:
            return obj.run(sites)
        except KeyboardInterrupt:
            logger.warning("bye")

    def run(self, urls: list[str]) -> None:
        in_q = mp.JoinableQueue()
        out_q = mp.Queue()
        seen = mp.Manager().dict()

        for url, path in itertools.product(urls, KNOWN_PATHES):
            in_q.put_nowait(urljoin(url, path))

        logger.info("Directory scanning started")

        workers = [
            Worker(in_q=in_q, out_q=out_q, seen=seen, timeout=self.timeout)
            for _ in range(self.workers_num)
        ]

        out_t = OutputThread(queue=out_q, stream=self.output)
        out_t.start()

        in_q.join()

        for _ in range(self.workers_num):
            in_q.put(None)

        for w in workers:
            w.join()

        out_q.put(None)
        out_t.join()

        logger.info("Finished!")

    @staticmethod
    def configure_logger(args: NameSpace) -> None:
        logger.addHandler(ColorHandler())
        logger.setLevel([logging.INFO, logging.DEBUG][args.debug])


if __name__ == "__main__":
    sys.exit(SpyDir.cli())
