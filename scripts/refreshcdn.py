import os
import asyncio
from typing import List,Tuple

import httpx
from loguru import logger

class RefreshCDN(object):
    def __init__(self):
        self.root = os.getcwd()
        self.targets = [
            ("rules", os.path.join(self.root, "rules")),
            ("sources/upstream", os.path.join(self.root, "sources", "upstream")),
        ]
        self.blockList = [
            "apple-cn.txt",
            "black.txt",
            "china.txt",
            "CN-ip-cidr.txt",
            "direct-list.txt",
            "domain.txt",
            "google-cn.txt",
            "myblock.txt",
            "white.txt"
        ]
        self.repo = self._resolve_repo()
        self.branch = self._resolve_branch()

    def _resolve_repo(self) -> str:
        repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
        if repo:
            return repo
        url = self._get_git_origin_url()
        return self._parse_repo_from_url(url)

    def _resolve_branch(self) -> str:
        ref = os.environ.get("GITHUB_REF", "")
        if ref.startswith("refs/heads/"):
            return ref[len("refs/heads/"):].strip() or "main"
        for key in ("GITHUB_REF_NAME", "GITHUB_HEAD_REF", "GITHUB_BASE_REF"):
            value = os.environ.get(key)
            if value:
                return value.strip()
        return "main"

    def _get_git_origin_url(self) -> str:
        try:
            import subprocess
            return subprocess.check_output(
                ["git", "config", "--get", "remote.origin.url"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
        except Exception:
            return ""

    def _parse_repo_from_url(self, url: str) -> str:
        if not url:
            return ""
        url = url.strip()
        if url.endswith(".git"):
            url = url[:-4]
        import re
        match = re.search(r"github\\.com[:/](?P<repo>[^/]+/[^/]+)$", url)
        if match:
            return match.group("repo")
        return ""

    def __getRuleList(self, pwd:str) -> List[str]:
        L = []
        if not os.path.isdir(pwd):
            return L
        for fileName in os.listdir(pwd):
            if os.path.isfile(os.path.join(pwd, fileName)) and fileName not in self.blockList:
                L.append(fileName)
        return L

    async def __refresh(self, base_dir: str, fileName: str):
        try:
            if not self.repo:
                logger.warning("refresh skipped: repo not resolved")
                return
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    "https://purge.jsdelivr.net/gh/%s@%s/%s/%s"
                    % (self.repo, self.branch, base_dir, fileName)
                )
                response.raise_for_status()
                status = response.json().get("status", "")
                logger.info(f'%s refresh status: %s' % (fileName, status))
        except Exception as e:
            logger.error(f'%s refresh failed: %s' % (fileName, e))

    def refresh(self):
        # 启动异步循环
        loop = asyncio.get_event_loop()
        # 添加异步任务
        taskList = []
        for base_dir, pwd in self.targets:
            ruleList = self.__getRuleList(pwd)
            for rule in ruleList:
                logger.info("refresh %s/%s..." % (base_dir, rule))
                task = asyncio.ensure_future(self.__refresh(base_dir, rule))
                taskList.append(task)
        # 等待异步任务结束
        if taskList:
            loop.run_until_complete(asyncio.wait(taskList))

if __name__ == '__main__':
    cdn = RefreshCDN()
    cdn.refresh()
