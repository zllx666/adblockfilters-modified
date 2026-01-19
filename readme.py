import re
import os
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
        self.proxyList = [
            "",
            "https://testingcf.jsdelivr.net/gh"
        ]

    def getRules(self) -> List[Rule]:
        logger.info("resolve readme...")
        self.ruleList = []
        with open(self.filename, "r") as f:
            for line in f:
                line = line.replace('\r', '').replace('\n', '')
                if line.find('|')==0 and line.rfind('|')==len(line)-1:
                    rule = list(map(lambda x: x.strip(), line[1:-1].split('|')))
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

    def __subscribeLink(self, fileName:str, url:str=None):
        link = ""

        if url:
            link += " [原始链接](%s) |"%(url)
        else:
            link += " [原始链接](https://raw.githubusercontent.com/Aethersailor/adblockfilters-modified/main/rules/%s) |"%(fileName)
        
        for i in range(1, len(self.proxyList)):
            proxy = self.proxyList[i]
            link_name = "加速链接" if len(self.proxyList) == 2 else "加速链接%d" % i
            if proxy.startswith("https://testingcf.jsdelivr.net/"):
                link += " [%s](%s/Aethersailor/adblockfilters-modified@main/rules/%s) |"%(link_name, proxy, fileName)
            else:
                link += " [%s](%s/https://raw.githubusercontent.com/Aethersailor/adblockfilters-modified/main/rules/%s) |"%(link_name, proxy, fileName)
        
        return link
    
    def regenerate(self):
        logger.info("regenerate readme...")
        if os.path.exists(self.filename):
            os.remove(self.filename)
        
        with open(self.filename, 'a') as f:
            f.write("# AdBlock DNS Filters Modified\n")
            f.write("adblockfilters 去广告合并规则增强版，每天更新一次。  \n")
            f.write("\n")

            f.write("## 说明\n")
            f.write("1. 定时从上游各规则源获取更新，合并去重。\n")
            f.write("2. 使用本地 SmartDNS 对上游各规则源拦截的域名进行解析，去除已无法解析的域名。（上游各规则源中存在大量已无法解析的域名，无需加入拦截规则）\n")
            f.write("3. 本项目仅对上游规则进行合并、去重、去除无效域名，不做任何修改。如发现误拦截情况，可在 `rules/white2.txt` 中自行添加白名单，或临时添加放行规则（如 `@@||www.example.com^$important`），并向上游规则反馈。\n")
            f.write("\n")

            f.write("## 相比原版 adblockfilters 的改进与新增\n")
            f.write("1. 大幅改进处理逻辑。优化后，处理六十万条上游规则只需要不到一个小时的时间。\n")
            f.write("2. 改进了中国规则和无效规则的处理流程，现在每次生成规则前均会对这两类规则进行验证，不再使用历史数据。\n")
            f.write("3. 白名单自动同步上游仓库，并支持 `rules/white2.txt` 本地补充合并。\n")
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
            f.write("   - HaGeZi's The World's Most Abused TLDs\n")
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
            f.write("2. 已对 testingcf.jsdelivr.net CDN 缓存进行主动刷新，但仍存在一定刷新延时\n")
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
            tmp += " 更新日期 |\n"
            f.write(tmp)
            tmp = "| " + ":- | " * ( 2 + len(self.proxyList) + 1) + "\n"
            f.write(tmp)
            for rule in self.ruleList:
                f.write("| %s | %s |%s %s |\n" % (rule.name, rule.type, self.__subscribeLink(rule.filename, rule.url),rule.latest))
            f.write("\n")
            
            f.write("## Star History\n")
            f.write("[![Star History Chart](https://api.star-history.com/svg?repos=Aethersailor/adblockfilters-modified&type=Date)](https://star-history.com/#Aethersailor/adblockfilters-modified&Date)\n")
            '''

            '''
