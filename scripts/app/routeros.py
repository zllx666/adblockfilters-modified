import os
import shutil
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase


class RouterOS(APPBase):
    _DEFAULT_MAX_BYTES = 95 * 1024 * 1024
    _ENTRY_BUDGET_MARGIN = 16 * 1024

    def __init__(self, blockList: List[str], unblockList: List[str], filterDict: Dict[str, str], filterList: List[str], filterList_var: List[str], ChinaSet: Set[str], fileName: str, sourceRule: str):
        super(RouterOS, self).__init__(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, fileName, sourceRule)

    def _get_max_bytes(self) -> int:
        raw = os.environ.get("ROUTEROS_MAX_BYTES")
        if not raw:
            return self._DEFAULT_MAX_BYTES

        try:
            value = int(raw)
            if value > 0:
                return value
        except Exception:
            pass

        logger.warning(f"Invalid ROUTEROS_MAX_BYTES={raw}, fallback to {self._DEFAULT_MAX_BYTES}")
        return self._DEFAULT_MAX_BYTES

    def generate(self, isLite=False):
        try:
            if isLite:
                logger.info("generate adblock RouterOS Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
            else:
                logger.info("generate adblock RouterOS...")
                fileName = self.fileName
                blockList = self.blockList

            if os.path.exists(fileName):
                os.remove(fileName)

            max_bytes = self._get_max_bytes()
            entry_budget = max(0, max_bytes - self._ENTRY_BUDGET_MARGIN)
            temp_entries = fileName + ".entries.tmp"
            included_count = 0
            written_bytes = 0
            truncated = False

            try:
                with open(temp_entries, "w", encoding="utf-8", newline="\n") as f:
                    for domain in blockList:
                        line_v4 = "ip dns static add address=240.0.0.1 name=%s\n" % (domain)
                        line_v6 = "ip dns static add address=:: name=%s\n" % (domain)
                        line_bytes = len(line_v4.encode("utf-8")) + len(line_v6.encode("utf-8"))
                        if written_bytes + line_bytes > entry_budget:
                            truncated = True
                            break
                        f.write(line_v4)
                        f.write(line_v6)
                        written_bytes += line_bytes
                        included_count += 1

                header = [
                    "#\n",
                    "# Title: AdBlock RouterOS Lite\n" if isLite else "# Title: AdBlock RouterOS\n",
                    "# Description: 适用于 RouterOS 的去广告合并规则，每 12 小时更新一次。规则源：%s。Lite 版仅针对国内域名拦截。\n" % (self.sourceRule)
                    if isLite else
                    "# Description: 适用于 RouterOS 的去广告合并规则，每 12 小时更新一次。规则源：%s。\n" % (self.sourceRule),
                    "# Homepage: %s\n" % (self.homepage),
                    "# Source: %s/%s\n" % (self.source, os.path.basename(fileName)),
                    "# Version: %s\n" % (self.version),
                    "# Last modified: %s\n" % (self.time),
                    "# Blocked domains: %s\n" % (included_count),
                ]
                if truncated:
                    header.append(
                        "# Note: Truncated to %s/%s domains to keep file size under %s bytes (GitHub file limit).\n"
                        % (included_count, len(blockList), max_bytes)
                    )
                header.append("#\n")

                with open(fileName, "w", encoding="utf-8", newline="\n") as out:
                    out.writelines(header)
                    with open(temp_entries, "r", encoding="utf-8", newline="\n") as src:
                        shutil.copyfileobj(src, out)
            finally:
                if os.path.exists(temp_entries):
                    os.remove(temp_entries)

            if truncated:
                logger.warning(
                    f"adblock RouterOS{' Lite' if isLite else ''} truncated: "
                    f"keep={included_count}, total={len(blockList)}, max_bytes={max_bytes}"
                )
            elif isLite:
                logger.info("adblock RouterOS Lite: block=%d" % (included_count))
            else:
                logger.info("adblock RouterOS: block=%d" % (included_count))
        except Exception as e:
            logger.error("%s" % (e))
