import re
import os
import subprocess
import time
import json
from datetime import datetime, timedelta, timezone
from typing import List

from loguru import logger

class Rule(object):
    def __init__(self, name:str, type:str, url:str, latest:str, update:bool=False):
        self.name = name
        safe_name = self.name.replace(' ', '_')
        for ch in ['/', '\\', ':', '*', '?', '"', '<', '>', '|']:
            safe_name = safe_name.replace(ch, '_')
        self.filename = safe_name + '.txt'
        self.type = type
        self.url = url
        self.latest = latest
        self.update = update

# redme文件操作
class ReadMe(object):
    def __init__(self, filename:str):
        self.filename = filename
        self.ruleList:List[Rule] = []
        self.accel_size_threshold = 20 * 1024 * 1024
        self.proxyList = [
            "",
            "https://testingcf.jsdelivr.net/gh",
        ]
        self.repo = self._resolve_repo()
        self.branch = self._resolve_branch()

    def getRules(self) -> List[Rule]:
        logger.info("resolve readme...")
        self.ruleList = []
        with open(self.filename, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line.find('|')==0 and line.rfind('|')==len(line)-1:
                    rule = list(map(lambda x: x.strip(), line[1:-1].split('|')))
                    if len(rule) < 4:
                        continue
                    if rule[2].find('(') > 0 and rule[2].find(')') > 0 and rule[1].find('(') < 0:
                        url = rule[2][rule[2].find('(')+1:rule[2].find(')')]
                        matchObj1 = re.match('(http|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)
                        if matchObj1:
                            self.ruleList.append(Rule(rule[0], rule[1], url, rule[-1]))
        return self.ruleList

    def getRulesNames(self) -> str:
        names = ""
        
        for rule in self.ruleList:
            names += rule.name + '、'
        
        return names[:-1]

    def setRules(self, ruleList:List[Rule]):
        self.ruleList = ruleList

    def _get_local_path(self, base_dir: str, fileName: str) -> str:
        base_dir = base_dir.strip("/")
        base_root = os.path.dirname(self.filename)
        return os.path.join(base_root, base_dir, fileName)

    def _should_use_boki(self, base_dir: str, fileName: str) -> bool:
        if base_dir.strip("/") != "rules":
            return False
        try:
            return os.path.getsize(self._get_local_path(base_dir, fileName)) >= self.accel_size_threshold
        except Exception:
            return False

    def __subscribeLink(self, fileName:str, url:str=None, base_dir:str="rules"):
        link = ""
        base_dir = base_dir.strip("/")
        raw_url = ""

        if url:
            link += " [原始链接](%s) |"%(url)
        else:
            raw_url = "https://raw.githubusercontent.com/%s/%s/%s/%s" % (
                self.repo,
                self.branch,
                base_dir,
                fileName,
            )
            link += " [原始链接](%s) |" % raw_url
        
        for i in range(1, len(self.proxyList)):
            proxy = self.proxyList[i]
            link_name = "加速链接" if len(self.proxyList) == 2 else "加速链接%d" % i
            if raw_url and self._should_use_boki(base_dir, fileName):
                link += " [%s](https://github.boki.moe/%s) |"%(link_name, raw_url)
                continue
            if proxy.rstrip("/").endswith("/gh"):
                link += " [%s](%s/%s@%s/%s/%s) |"%(
                    link_name,
                    proxy,
                    self.repo,
                    self.branch,
                    base_dir,
                    fileName,
                )
            else:
                link += " [%s](%s/https://raw.githubusercontent.com/%s/%s/%s/%s) |"%(
                    link_name,
                    proxy,
                    self.repo,
                    self.branch,
                    base_dir,
                    fileName,
                )
        
        return link
    
    def regenerate(self):
        logger.info("regenerate readme...")
        if os.path.exists(self.filename):
            os.remove(self.filename)
        
        beijing_tz = timezone(timedelta(hours=8))
        update_time = datetime.now(beijing_tz).strftime("%Y/%m/%d %H:%M:%S") + " (UTC+08:00)"
        total_rules, china_rules = self._get_rule_counts()
        upstream_raw, upstream_unique, upstream_dedupe_rate = self._get_upstream_stats()
        effective_count, effective_ratio = self._get_effective_stats()
        source_meta = self._load_source_meta()

        with open(self.filename, 'a') as f:
            f.write("# AdBlock DNS Filters Modified\n")
            f.write("adblockfilters 去广告合并规则增强版，每天更新一次。  \n")
            f.write("\n")
            f.write("| 指标 | 数值 |\n")
            f.write("| :- | :- |\n")
            f.write("| 上次更新（北京时间） | %s |\n" % update_time)
            f.write("| 上游规则总数（去重前） | %s |\n" % (upstream_raw if upstream_raw is not None else "N/A"))
            f.write("| 上游规则总数（去重后） | %s |\n" % (upstream_unique if upstream_unique is not None else "N/A"))
            f.write("| 上游规则去重率 | %s |\n" % (upstream_dedupe_rate if upstream_dedupe_rate is not None else "N/A"))
            f.write("| 有效规则数量（可解析） | %s |\n" % (effective_count if effective_count is not None else "N/A"))
            f.write("| 有效规则占比（检测域名） | %s |\n" % (effective_ratio if effective_ratio is not None else "N/A"))
            f.write("| 成品规则总数 | %s |\n" % (total_rules if total_rules is not None else "N/A"))
            f.write("| 中国规则数（Lite） | %s |\n" % (china_rules if china_rules is not None else "N/A"))
            f.write("\n")

            f.write("## 说明\n")
            f.write("1. 定时从上游各规则源获取更新，合并去重。\n")
            f.write("2. 使用本地 SmartDNS 对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）\n")
            f.write("3. 本项目仅对上游规则进行合并、去重、去除无效域名，不做任何修改。如发现误拦截情况，可在 `sources/local/white2.txt` 中自行添加白名单，或临时添加放行规则（如 `@@||www.example.com^$important`），并向上游规则反馈。\n")
            f.write("\n")

            f.write("## 相比原版 adblockfilters 的改进与新增\n")
            f.write("1. 改进了处理逻辑，缩短工作流运行时间。\n")
            f.write("2. 改进了中国规则和无效规则的处理流程，现在每次生成规则前均会对这两类规则进行验证，不再使用历史数据。\n")
            f.write("3. 白名单自动同步上游仓库，并支持 `sources/local/white2.txt` 本地补充合并。\n")
            f.write("4. 域名提取与规则解析更完善，覆盖更多 filter/dns/host 规则格式，减少漏提取。\n")
            f.write("5. 新增/独有规则源（相对原版，详见下表）：\n")
            f.write("   - AdGuard Annoyances\n")
            f.write("   - AdGuard Tracking Protection\n")
            f.write("   - anti-AD\n")
            f.write("   - CERT.PL's Warning List\n")
            f.write("   - HageziMultiPro\n")
            f.write("   - HaGeZi's Apple Tracker Blocklist\n")
            f.write("   - HaGeZi's Badware Hoster Blocklist\n")
            f.write("   - HaGeZi's OPPO & Realme Tracker Blocklist\n")
            f.write("   - HaGeZi's Windows/Office Tracker Blocklist\n")
            f.write("   - HaGeZi's Xiaomi Tracker Blocklist\n")
            f.write("   - HaGeZi's Vivo Tracker Blocklist\n")
            f.write("   - HaGeZi's Samsung Tracker Blocklist\n")
            f.write("   - HaGeZi's Gambling Blocklist\n")
            f.write("   - Malicious URL Blocklist\n")
            f.write("   - OISD Big\n")
            f.write("   - Online Malicious URL Blocklist\n")
            f.write("   - PeterLowe\n")
            f.write("   - Phishing URL Blocklist\n")
            f.write("   - Scam Blocklist\n")
            f.write("   - SmartTV\n")
            f.write("   - Stalkerware\n")
            f.write("   - uBlock Ads\n")
            f.write("   - uBlock Badware risks\n")
            f.write("   - uBlock Privacy\n")
            f.write("\n")

            f.write("## 订阅链接\n")
            f.write("1. 规则x’为规则x的 Lite 版，仅针对国内域名拦截，体积较小（如添加完整规则报错数量限制，请尝试 Lite 规则）\n")
            f.write("2. 默认使用 testingcf.jsdelivr.net CDN，加速大文件会自动切换至 github.boki.moe\n")
            f.write("3. AdGuard 等浏览器插件使用规则1 + 规则2（规则2为规则1的补充，仅适用浏览器插件）\n")
            f.write("\n")
            tmp = "| 规则 | 原始链接 |"
            for i in range(1, len(self.proxyList)):
                if len(self.proxyList) == 2:  # Only one CDN
                    tmp += " 加速链接 |"
                else:
                    tmp += " 加速链接%d |"%(i)
            tmp += " 适配说明 |\n"
            f.write(tmp)
            tmp = "| " + ":- | " * ( 1 + len(self.proxyList) + 1) + "\n"
            f.write(tmp)
            f.write("| 规则1 |" + self.__subscribeLink("adblockdns.txt") + " AdGuard、AdGuard Home 等 |\n")
            f.write("| 规则1' |" + self.__subscribeLink("adblockdnslite.txt") + " AdGuard、AdGuard Home 等 |\n")
            f.write("| 规则2 |" + self.__subscribeLink("adblockfilters.txt") + " AdGuard 等 |\n")
            f.write("| 规则2' |" + self.__subscribeLink("adblockfilterslite.txt") + " AdGuard 等 |\n")
            f.write("| 规则3 |" + self.__subscribeLink("adblockdomain.txt") + " InviZible Pro、personalDNSfilter |\n")
            f.write("| 规则3' |" + self.__subscribeLink("adblockdomainlite.txt") + " InviZible Pro、personalDNSfilter |\n")
            f.write("| 规则4 |" + self.__subscribeLink("adblockdnsmasq.txt") + " DNSMasq |\n")
            f.write("| 规则4' |" + self.__subscribeLink("adblockdnsmasqlite.txt") + " DNSMasq |\n")
            f.write("| 规则5 |" + self.__subscribeLink("adblocksmartdns.conf") + " SmartDNS |\n")
            f.write("| 规则5' |" + self.__subscribeLink("adblocksmartdnslite.conf") + " SmartDNS |\n")
            f.write("| 规则6 |" + self.__subscribeLink("adblockclash.list") + " Shadowrocket |\n")
            f.write("| 规则6' |" + self.__subscribeLink("adblockclashlite.list") + " Shadowrocket |\n")
            f.write("| 规则7 |" + self.__subscribeLink("adblockqx.conf") + " QuantumultX |\n")
            f.write("| 规则7' |" + self.__subscribeLink("adblockqxlite.conf") + " QuantumultX |\n")
            f.write("| 规则8 |" + self.__subscribeLink("adblockmihomo.yaml") + " Clash Meta(Mihomo) yaml |\n")
            f.write("| 规则8' |" + self.__subscribeLink("adblockmihomolite.yaml") + " Clash Meta(Mihomo) yaml |\n")
            f.write("| 规则9 |" + self.__subscribeLink("adblockmihomo.mrs") + " Clash Meta(Mihomo) mrs |\n")
            f.write("| 规则9' |" + self.__subscribeLink("adblockmihomolite.mrs") + " Clash Meta(Mihomo) mrs |\n")
            f.write("| 规则10 |" + self.__subscribeLink("adblockhosts.txt") + " Hosts |\n")
            f.write("| 规则10' |" + self.__subscribeLink("adblockhostslite.txt") + " Hosts |\n")
            f.write("| 规则11 |" + self.__subscribeLink("adblocksingbox.json") + " sing-box 1.12.x json |\n")
            f.write("| 规则11' |" + self.__subscribeLink("adblocksingboxlite.json") + " sing-box 1.12.x json |\n")
            f.write("| 规则12 |" + self.__subscribeLink("adblocksingbox.srs") + " sing-box 1.12.x srs |\n")
            f.write("| 规则12' |" + self.__subscribeLink("adblocksingboxlite.srs") + " sing-box 1.12.x srs |\n")
            f.write("| 规则13 |" + self.__subscribeLink("adblockloon.list") + " Loon |\n")
            f.write("| 规则13' |" + self.__subscribeLink("adblockloonlite.list") + " Loon |\n")
            f.write("| 规则14 |" + self.__subscribeLink("adblocksurge.list") + " Surge |\n")
            f.write("| 规则14' |" + self.__subscribeLink("adblocksurgelite.list") + " Surge |\n")
            f.write("\n")

            f.write("## 上游规则源\n")
            f.write("1. 感谢各位广告过滤规则维护大佬们的辛苦付出。\n")
            f.write("\n")

            tmp = "| 规则 | 类型 | 原始链接 |"
            for i in range(1, len(self.proxyList)):
                if len(self.proxyList) == 2:  # Only one CDN
                    tmp += " 加速链接 |"
                else:
                    tmp += " 加速链接%d |"%(i)
            tmp += " 规则数量 | 更新日期 |\n"
            f.write(tmp)
            tmp = "| " + ":- | " * ( 2 + len(self.proxyList) + 2) + "\n"
            f.write(tmp)
            for rule in self.ruleList:
                count = self._get_source_count(rule, source_meta)
                count_text = str(count) if count is not None else "N/A"
                f.write("| %s | %s |%s %s | %s |\n" % (
                    rule.name,
                    rule.type,
                    self.__subscribeLink(rule.filename, rule.url, base_dir="sources/upstream"),
                    count_text,
                    rule.latest,
                ))
            f.write("\n")
            
            f.write("## Star History\n")
            f.write('<a href="https://www.star-history.com/#%s&Date">\n' % self.repo)
            f.write(' <picture>\n')
            f.write('   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=%s&type=Date&theme=dark" />\n' % self.repo)
            f.write('   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=%s&type=Date" />\n' % self.repo)
            f.write('   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=%s&type=Date" />\n' % self.repo)
            f.write(' </picture>\n')
            f.write('</a>\n')
            '''

            '''

    def _get_rule_counts(self):
        base_dir = os.path.dirname(self.filename)
        total_path = os.path.join(base_dir, "rules", "adblockfilters.txt")
        china_path = os.path.join(base_dir, "rules", "adblockfilterslite.txt")
        total_rules = self._read_blocked_filters(total_path)
        china_rules = self._read_blocked_filters(china_path)
        return total_rules, china_rules

    def _read_blocked_filters(self, path: str):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("! Blocked Filters:"):
                        value = line.split(":", 1)[1].strip()
                        if value.isdigit():
                            return int(value)
                        break
        except Exception:
            return None

        return self._count_rule_lines(path)

    def _count_rule_lines(self, path: str):
        try:
            count = 0
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("!"):
                        continue
                    count += 1
            return count
        except Exception:
            return None

    def _format_ratio(self, numerator, denominator):
        if numerator is None or denominator is None or denominator == 0:
            return None
        return "{:.2%}".format(numerator / denominator)

    def _get_upstream_stats(self):
        base_dir = os.path.dirname(self.filename)
        upstream_dir = os.path.join(base_dir, "sources", "upstream")
        raw_count = 0
        unique_rules = set()
        if not self.ruleList:
            return None, None, None
        for rule in self.ruleList:
            path = os.path.join(upstream_dir, rule.filename)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith(("#", "!")):
                            continue
                        raw_count += 1
                        unique_rules.add(line)
            except Exception:
                continue
        unique_count = len(unique_rules) if raw_count else 0
        dedupe_rate = self._format_ratio(raw_count - unique_count, raw_count)
        return raw_count, unique_count, dedupe_rate

    def _get_effective_stats(self):
        base_dir = os.path.dirname(self.filename)
        build_dir = os.path.join(base_dir, "build")
        invalid_path = os.path.join(build_dir, "black.txt")
        domain_path = os.path.join(build_dir, "domain.txt")
        invalid_count = self._count_non_empty_lines(invalid_path)
        domain_count = self._count_non_empty_lines(domain_path)
        if invalid_count is None or domain_count is None:
            return None, None
        effective_count = max(domain_count - invalid_count, 0)
        effective_ratio = self._format_ratio(effective_count, domain_count)
        return effective_count, effective_ratio

    def _load_source_meta(self) -> dict:
        base_dir = os.path.dirname(self.filename)
        meta_path = os.path.join(base_dir, "sources", "upstream", ".source_meta.json")
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _count_non_empty_lines(self, path: str) -> int:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                count = 0
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith(("#", "!")):
                        continue
                    count += 1
                return count
        except Exception:
            return 0

    def _get_source_count(self, rule: Rule, meta: dict):
        if meta:
            entry = meta.get(rule.filename)
            if isinstance(entry, dict):
                lines = entry.get("lines")
                if isinstance(lines, int):
                    return lines
        base_dir = os.path.dirname(self.filename)
        source_path = os.path.join(base_dir, "sources", "upstream", rule.filename)
        if os.path.exists(source_path):
            return self._count_non_empty_lines(source_path)
        return None

    def _resolve_repo(self) -> str:
        repo = os.environ.get("GITHUB_REPOSITORY")
        if repo:
            return repo.strip()

        url = self._get_git_origin_url()
        repo = self._parse_repo_from_url(url)
        if repo:
            return repo

        return "Aethersailor/adblockfilters-modified"

    def _resolve_branch(self) -> str:
        ref = os.environ.get("GITHUB_REF", "")
        if ref.startswith("refs/heads/"):
            return ref[len("refs/heads/"):].strip()

        for key in ("GITHUB_REF_NAME", "GITHUB_HEAD_REF", "GITHUB_BASE_REF"):
            value = os.environ.get(key)
            if value:
                return value.strip()

        try:
            output = subprocess.check_output(
                ["git", "remote", "show", "origin"],
                stderr=subprocess.DEVNULL,
                text=True,
            )
            match = re.search(r"HEAD branch: (.+)", output)
            if match:
                return match.group(1).strip()
        except Exception:
            pass

        return "main"

    def _get_git_origin_url(self) -> str:
        try:
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
        match = re.search(r"github\\.com[:/](?P<repo>[^/]+/[^/]+)$", url)
        if match:
            return match.group("repo")
        return ""
