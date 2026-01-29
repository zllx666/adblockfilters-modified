import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor,as_completed
from typing import List,Dict,Set,Tuple

from loguru import logger
from tld import get_tld

from app import APPBase, AdGuard, AdGuardHome, DNSMasq, Hosts, InviZible, Loon, Mihomo, MosDNS, QuantumultX, Shadowrocket, SingBox, SmartDNS, Surge
from readme import Rule
from resolver import Resolver, FilterDomainInfo

class Filter(object):
    def __init__(self, ruleList:List[Rule], source_dirs:List[str], work_dir:str, output_dir:str):
        self.ruleList = ruleList
        self.source_dirs = source_dirs
        self.work_dir = work_dir
        self.output_dir = output_dir

    def __normalize_domain(self, domain: str) -> str:
        domain = domain.strip().lower()
        if domain.endswith('.'):
            domain = domain[:-1]
        try:
            domain = domain.encode("idna").decode("ascii")
        except Exception:
            pass
        return domain
    
    # 获取拦截规则
    def __getFilters(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, FilterDomainInfo]]:
        def dictadd(d1:Dict[str,Set], d2:Dict[str,Set]) -> Dict[str,Set]:
            d3 = dict()
            s = set.union(set(d1), set(d2))
            for item in s:
                d3[item] = set.union(d1.get(item, set()), d2.get(item, set()))
            return d3
        def merge_filter_info(old: FilterDomainInfo, new: FilterDomainInfo) -> FilterDomainInfo:
            if not old:
                return new
            if not new:
                return old
            domains = old.domains | new.domains
            if old.source == "target" or new.source == "target":
                source = "target"
            elif old.source == "context" or new.source == "context":
                source = "context"
            else:
                source = "none"
            return FilterDomainInfo(domains, source)

        thread_pool = ThreadPoolExecutor(max_workers=os.cpu_count() if os.cpu_count() > 4 else 4)
        resolver = Resolver(self.source_dirs)
        # 线程池解析
        taskList = []
        for rule in self.ruleList:
            logger.info("resolve %s..."%(rule.name))
            if rule.type == "host":
                taskList.append(thread_pool.submit(resolver.resolveHost, rule))
            if rule.type == "dns":
                taskList.append(thread_pool.submit(resolver.resolveDNS, rule))
            if rule.type == "filter":
                taskList.append(thread_pool.submit(resolver.resolveFilter, rule))
        # 添加收集的补充规则
        rule = Rule("myblock", "dns", "", "")
        taskList.append(thread_pool.submit(resolver.resolveDNS, rule))
        
        # 获取解析结果
        blockDict:Dict[str,Set[str]] = dict()
        unblockDict:Dict[str,Set[str]] = dict()
        filterDict:Dict[str,FilterDomainInfo] = dict()
        for future in as_completed(taskList):
            try:
                __blockDict,__unblockDict,__filterDict = future.result()
                blockDict = dictadd(blockDict, __blockDict)
                unblockDict = dictadd(unblockDict, __unblockDict)
                for filter,domain_info in __filterDict.items():
                    if filter in filterDict:
                        filterDict[filter] = merge_filter_info(filterDict[filter], domain_info)
                    else:
                        filterDict[filter] = domain_info
            except Exception as e:
                logger.error("%s"%(e))

        return blockDict,unblockDict,filterDict
    
    # 获取黑名单，经测试已无法解析的域名
    def __getBlackList(self, fileName:str) -> Set[str]:
        logger.info("resolve black list...")
        blackSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                blackList = f.readlines()
                blackSet = set(map(lambda x: x.replace("\n", ""), blackList))
        logger.info("black list: %d"%(len(blackSet)))
        return blackSet

    # 获取白名单，收集的误杀规则
    def __getWhiteList(self, fileName:str) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        logger.info("resolve white list...")
        whiteRules:Set[str] = set()
        whiteDomains:Set[str] = set()
        whiteWildcardAll:Set[str] = set()  # +.example.com -> root + subdomains
        whiteWildcardSub:Set[str] = set()  # *.example.com -> subdomains only
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                for line in f.readlines():
                    line = line.replace("\n", "").strip()
                    if not line or line.startswith("#") or line.startswith("!"):
                        continue
                    whiteRules.add(line)
                    if line.startswith("+.") or line.startswith("*."):
                        domain = self.__normalize_domain(line[2:])
                        try:
                            res = get_tld(domain, fix_protocol=True, as_object=True)
                            if res.fld:
                                fld = self.__normalize_domain(res.fld)
                                if line.startswith("+."):
                                    whiteWildcardAll.add(fld)
                                else:
                                    whiteWildcardSub.add(fld)
                        except Exception:
                            pass
                        continue
                    try:
                        ipaddress.ip_address(line)
                        whiteDomains.add(line)
                        continue
                    except Exception:
                        pass
                    try:
                        res = get_tld(line, fix_protocol=True, as_object=True)
                        if res.fld:
                            whiteDomains.add(self.__normalize_domain(line))
                    except Exception:
                        pass
        logger.info("white list: %d"%(len(whiteDomains)))
        return whiteRules, whiteDomains, whiteWildcardAll, whiteWildcardSub
    
    def __getWhiteDict(self, whiteDomains:Set[str]) -> Dict[str,Set[str]]:
        whiteDict = dict()

        for address in whiteDomains:
            try:
                res = get_tld(address, fix_protocol=True, as_object=True)
                fld = res.fld
                subdomain = res.subdomain
                if fld not in whiteDict:
                    whiteDict[fld] = {subdomain}
                else:
                    whiteDict[fld] |= {subdomain}
            except Exception as e:
                pass
        
        return whiteDict
    
    # 获取 China domain 清单，国内域名
    def __getChinaList(self, fileName:str) -> Set[str]:
        logger.info("resolve China list...")
        ChinaSet = set()
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                ChinaList = f.readlines()
                ChinaSet = set(map(lambda x: x.replace("\n", ""), ChinaList))
        logger.info("China list: %d"%(len(ChinaSet)))
        return ChinaSet
    
    # 去重、排序
    def __domainSort(self, domainDict:Dict[str, Set[str]], blackSet:Set[str], whiteDict:Dict[str,Set[str]], whiteWildcardAll:Set[str], whiteWildcardSub:Set[str]) -> Tuple[List[str], Set[str]]:
        def repetition(l): # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
            l = sorted(l, key = lambda item:len(item), reverse=False) # 按从短到长排序
            if len(l) < 2:
                return l
            if l[0] == '':
                return l[:1]
            tmp = set()
            for i in range(len(l) - 1):
                for j in range(i+1, len(l)):
                    if l[j].endswith("." + l[i]):
                        tmp.add(l[j])
            l = list(set(l)-tmp)
            l.sort()
            return l
        def get_domain(fld, subdomain):
            if len(subdomain) > 0:
                domain = ("%s.%s")%(subdomain, fld)
            else:
                domain = ("%s")%(fld)
            return domain

        domanList = []
        domanSet_all = set()
        fldList = list(domainDict.keys())
        fldList.sort() # 排序
        for fld in fldList:
            if fld in whiteWildcardAll:
                continue
            subdomainList_origin = list(domainDict[fld])
            if fld in whiteWildcardSub:
                subdomainList_origin = [item for item in subdomainList_origin if item == '']
            subdomainList_origin = list(set(subdomainList_origin) - whiteDict.get(fld, set())) # 去除需要保留的白名单域名
            subdomainList = repetition(subdomainList_origin) # 短域名已被拦截，则干掉所有长域名。如'a.example'、'b.example'、'example'，则只保留'example'
            for subdomain in subdomainList:
                subdomain_not_black = False
                for _subdomain in list(set(subdomainList_origin) - set(subdomainList)):
                    if len(subdomain) > 0:
                        if _subdomain.endswith("." + subdomain):
                            _domain = get_domain(fld, _subdomain)
                            if _domain not in blackSet:
                                subdomain_not_black = True
                                break
                    else:
                        _domain = get_domain(fld, _subdomain)
                        if _domain not in blackSet:
                            subdomain_not_black = True
                            break
                
                domain = get_domain(fld, subdomain)
                if domain not in blackSet:
                    domanList.append(domain)
                else:
                    if subdomain_not_black: # 只要子域名有一个未black，仍然保留
                        domanList.append(domain)

            # 全域名保留，用于后续验证连通性
            for subdomain in subdomainList_origin: 
                domain = get_domain(fld, subdomain)
                domanSet_all.add(domain)
            
        return domanList,domanSet_all

    def __filterSort(self, filterDict:Dict[str,FilterDomainInfo], blockSet:Set[str], unblockSet:Set[str], blackSet:Set[str], whiteRules:Set[str], whiteDomains:Set[str], whiteWildcardAll:Set[str], whiteWildcardSub:Set[str]) -> Tuple[List[str], List[str], Set[str]]:
        def in_domain_set(domain: str, domain_set: Set[str]) -> bool:
            if domain in domain_set:
                return True
            try:
                res = get_tld(domain, fix_protocol=True, as_object=True)
                fld = res.fld
            except Exception:
                fld = ''
            return bool(fld and fld in domain_set)
        domain_cache:Dict[str,Tuple[str,str]] = dict()
        def split_domain(domain: str) -> Tuple[str,str]:
            if domain in domain_cache:
                return domain_cache[domain]
            try:
                res = get_tld(domain, fix_protocol=True, as_object=True)
                fld = self.__normalize_domain(res.fld) if res.fld else ''
                subdomain = self.__normalize_domain(res.subdomain) if res.subdomain else ''
            except Exception:
                fld, subdomain = '', ''
            domain_cache[domain] = (fld, subdomain)
            return fld, subdomain
        def is_whitelisted(domain: str) -> bool:
            if domain in whiteDomains:
                return True
            try:
                ipaddress.ip_address(domain)
                return False
            except Exception:
                pass
            fld, subdomain = split_domain(domain)
            if not fld:
                return False
            if fld in whiteWildcardAll:
                return True
            if fld in whiteWildcardSub and subdomain:
                return True
            return False
        filterList = list(set(filterDict) - whiteRules) # 剔除白名单
        filterList.sort() # 排序
        # 与 adblockdns 去重
        filterList_var = []
        filterList_final = []
        domainSet_all = set()
        for filter in filterList:
            if filter.startswith('#%#var'):
                filterList_var.append(filter)
                continue
            
            domain_info = filterDict[filter]
            domains = domain_info.domains if domain_info and domain_info.source in {"target", "context"} else set()
            if domains:
                if all(is_whitelisted(domain) for domain in domains):
                    continue
                if all(in_domain_set(domain, blackSet) for domain in domains): # 剔除黑名单
                    continue
                if filter.startswith('@@'):
                    if all(in_domain_set(domain, unblockSet) for domain in domains): # 剔除 adblockdns 已放行
                        continue
                else:
                    if all(in_domain_set(domain, blockSet) for domain in domains): # 剔除 adblockdns 已拦截
                        continue
                for domain in domains:
                    domainSet_all.add(domain)
            
            filterList_final.append(filter)
        
        return filterList_var, filterList_final, domainSet_all

    # 生成用于域名连通性检测的全域名清单
    def __generateDomainBackup(self, domainSet, fileName:str):
        logger.info("generate domain backup...")
        if os.path.exists(fileName):
            os.remove(fileName)

        domainList = list(domainSet)
        domainList.sort() # 排序

        with open(fileName, 'a') as f:
            for domain in domainList:
                f.write("%s\n"%(domain))
        
        logger.info("domain backup: %d"%(len(domainList)))

    def generate(self, sourceRule, generate_rules: bool = True, generate_domain_backup: bool = True):
        # 从上游规则中提取规则
        blockDict,unblockDict,filterDict = self.__getFilters()

        # 提取黑名单、白名单、China domain
        blackSet = self.__getBlackList(self.work_dir + "/black.txt")  # 经测试已无法解析的域名
        whiteRules, whiteDomains, whiteWildcardAll, whiteWildcardSub = self.__getWhiteList(self.work_dir + "/white.txt")  # 收集的误杀规则
        whiteDict = self.__getWhiteDict(whiteDomains)
        ChinaSet = self.__getChinaList(self.work_dir + "/china.txt")  # 国内域名

        # 规则处理：合并、去重、排序、剔除剔除黑名单、剔除白名单
        blockList, blockSet_block = self.__domainSort(blockDict, blackSet, whiteDict, whiteWildcardAll, whiteWildcardSub)
        unblockList, unblockSet_unblock = self.__domainSort(unblockDict, blackSet, whiteDict, whiteWildcardAll, whiteWildcardSub)
        filterList_var, filterList, domainSet_filter = self.__filterSort(filterDict, set(blockList), set(unblockList), blackSet, whiteRules, whiteDomains, whiteWildcardAll, whiteWildcardSub)

        lite_candidates = []
        lite_unknown = 0
        lite_non_china = 0
        for f in filterList:
            info = filterDict[f]
            domains = info.domains if info else set()
            source = info.source if info else "none"
            if not domains or source == "none":
                lite_unknown += 1
                continue
            if source in {"target", "context"} and all(domain in ChinaSet for domain in domains):
                lite_candidates.append(f)
            else:
                lite_non_china += 1
        sample_size = min(20, len(lite_candidates))
        sample_mismatch = 0
        for f in lite_candidates[:sample_size]:
            domains = filterDict[f].domains
            if any(domain not in ChinaSet for domain in domains):
                sample_mismatch += 1
        logger.info(
            "lite filters: candidates=%d, unknown=%d, non_china=%d, sample=%d, sample_mismatch=%d"
            % (len(lite_candidates), lite_unknown, lite_non_china, sample_size, sample_mismatch)
        )

        if generate_rules:
            # 生成合并规则 AdGuard, AdGuardHome, DNSMasq, InviZible, SmartDNS等
            generaterList:List[APPBase] = [
                AdGuard     (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockfilters.txt",   sourceRule),
                AdGuardHome (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockdns.txt",       sourceRule),
                DNSMasq     (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockdnsmasq.txt",   sourceRule),
                Hosts       (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockhosts.txt",     sourceRule),
                InviZible   (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockdomain.txt",    sourceRule),
                Loon        (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockloon.list",      sourceRule),
                Mihomo      (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockmihomo.yaml",   sourceRule),
                QuantumultX (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockqx.conf",       sourceRule),
                Shadowrocket(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockclash.list",    sourceRule),
                SingBox     (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblocksingbox.json",  sourceRule),
                SmartDNS    (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblocksmartdns.conf", sourceRule),
                MosDNS      (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblockmosdns.txt",    sourceRule),
                Surge       (blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, self.output_dir + "/adblocksurge.list",     sourceRule),
            ]
            for g in generaterList:
                g.generateAll()
        
        # 生成用于域名连通性检测的全域名清单
        if generate_domain_backup:
            self.__generateDomainBackup(blockSet_block | unblockSet_unblock | domainSet_filter, self.work_dir + "/domain.txt")
