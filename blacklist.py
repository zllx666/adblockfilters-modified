import os
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import pytricia
from tld import get_tld
from loguru import logger
from dns.asyncresolver import Resolver as DNSResolver
from dns.rdatatype import RdataType as DNSRdataType


class ChinaDomian(object):
    def __init__(self, fileName, url):
        self.__fileName = fileName
        self.__url = url
        self.fullSet = set()
        self.domainSet = set()
        self.regexpSet = set()
        self.keywordSet = set()
        self.__update()
        self.__resolve()

    def __update(self):
        try:
            if os.path.exists(self.__fileName):
                os.remove(self.__fileName)
            
            with httpx.Client(timeout=30) as client:
                response = client.get(self.__url)
                response.raise_for_status()
                with open(self.__fileName,'wb') as f:
                    f.write(response.content)
        except Exception as e:
            logger.error("%s"%(e))
    
    def __isDomain(self, address):
        fld, subdomain = '', ''
        try:
            res = get_tld(address, fix_protocol=True, as_object=True)
            fld, subdomain = res.fld, res.subdomain
        except Exception:
            pass  # 静默处理非域名，避免大量错误日志
        finally:
            return fld, subdomain

    def __resolve(self):
        try:
            if not os.path.exists(self.__fileName):
                return
            
            with open(self.__fileName, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if '#' in line:
                        line = line[:line.find('#')].strip()
                    
                    # regexp
                    if line.startswith('regexp:'):
                        self.regexpSet.add(line[7:])
                        continue
                    
                    # keyword
                    if line.startswith('keyword:'):
                        self.keywordSet.add(line[8:])
                        continue
                    
                    if line.startswith('full:'):
                        domain = line[5:]
                    elif line.startswith('domain:'):
                        domain = line[7:]
                    else:
                        domain = line
                    fld, subdomian = self.__isDomain(domain)
                    if fld:
                        if subdomian:
                            self.fullSet.add(domain)
                        else:
                            self.domainSet.add(domain)
        except Exception as e:
            logger.error("%s"%(e))


class BlackList(object):
    def __init__(self):
        self.__ChinalistFile = os.getcwd() + "/rules/china.txt"
        self.__blacklistFile = os.getcwd() + "/rules/black.txt"
        self.__domainlistFile = os.getcwd() + "/rules/domain.txt"
        self.__domainlistFile_CN = os.getcwd() + "/rules/direct-list.txt"
        self.__domainlistUrl_CN = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/direct-list.txt"
        self.__domainlistFile_CN_Apple = os.getcwd() + "/rules/apple-cn.txt"
        self.__domainlistUrl_CN_Apple = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/apple-cn.txt"
        self.__domainlistFile_CN_Google = os.getcwd() + "/rules/google-cn.txt"
        self.__domainlistUrl_CN_Google = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/refs/heads/release/google-cn.txt"
        self.__iplistFile_CN = os.getcwd() + "/rules/CN-ip-cidr.txt"
        self.__iplistUrl_CN = "https://raw.githubusercontent.com/Aethersailor/geoip/refs/heads/release/text/cn-ipv4.txt"
        self.__maxTask = 3000  # 增大并发数以提升 DNS 解析吞吐量

    def __getDomainList(self):
        logger.info("resolve adblock dns backup...")
        domainList = []
        try:
            if os.path.exists(self.__domainlistFile):
                with open(self.__domainlistFile, 'r') as f:
                    domainList = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("adblock dns backup: %d"%(len(domainList)))
            return domainList
        
    def __getDomainSet_CN(self):
        logger.info("resolve China domain list...")
        fullSet,domainSet,regexpSet,keywordSet = set(),set(),set(),set()
        try:
            domain_cn = ChinaDomian(self.__domainlistFile_CN, self.__domainlistUrl_CN)
            domain_apple = ChinaDomian(self.__domainlistFile_CN_Apple, self.__domainlistUrl_CN_Apple)
            domain_google = ChinaDomian(self.__domainlistFile_CN_Google, self.__domainlistUrl_CN_Google)

            fullSet = domain_cn.fullSet | domain_apple.fullSet | domain_google.fullSet
            domainSet = domain_cn.domainSet | domain_apple.domainSet | domain_google.domainSet
            regexpSet = domain_cn.regexpSet | domain_apple.regexpSet | domain_google.regexpSet
            keywordSet = domain_cn.keywordSet | domain_apple.keywordSet | domain_google.keywordSet
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("China domain list: full[%d], domain[%d], regexp[%d], keyword[%d]"%(len(fullSet),len(domainSet),len(regexpSet),len(keywordSet)))
            return fullSet,domainSet,regexpSet,keywordSet
        
    def __getIPTrie_CN(self):
        """构建中国 IP 前缀树，使用 pytricia 实现 O(32) 时间复杂度的 CIDR 匹配"""
        logger.info("resolve China IP list...")
        pyt = pytricia.PyTricia()
        try:
            if os.path.exists(self.__iplistFile_CN):
                os.remove(self.__iplistFile_CN)
            
            with httpx.Client(timeout=30) as client:
                response = client.get(self.__iplistUrl_CN)
                response.raise_for_status()
                with open(self.__iplistFile_CN,'wb') as f:
                    f.write(response.content)
            
            if os.path.exists(self.__iplistFile_CN):
                with open(self.__iplistFile_CN, 'r') as f:
                    for line in f:
                        cidr = line.strip()
                        if cidr and not cidr.startswith('#'):
                            pyt.insert(cidr, True)
        except Exception as e:
            logger.error("%s"%(e))
        finally:
            logger.info("China IP Trie entries: %d"%(len(pyt)))
            return pyt
    
    async def __resolve(self, dnsresolver, domain):
        ipList = []
        try:
            query_object = await dnsresolver.resolve(qname=domain, rdtype="A")
            query_item = None
            for item in query_object.response.answer:
                if item.rdtype == DNSRdataType.A:
                    query_item = item
                    break
            if query_item is None:
                raise Exception("not A type")
            for item in query_item:
                ip = '{}'.format(item)
                if ip != "0.0.0.0":
                    ipList.append(ip)
        except Exception:
            pass  # 静默处理 DNS 解析失败，避免大量错误日志
        finally:
            return ipList

    async def __pingx(self, dnsresolver, domain, semaphore):
        async with semaphore:
            host = domain
            port = None
            ipList = []
            if domain.rfind(":") > 0:
                offset = domain.rfind(":")
                host = domain[ : offset]
                port = int(domain[offset + 1 : ])
            try:
                get_tld(host, fix_protocol=True, as_object=True)
            except Exception:
                port = 80
            if port:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=5  # 添加连接超时
                    )
                    writer.close()
                    await writer.wait_closed()
                    ipList.append(host)
                except Exception:
                    if port == 80:
                        port = 443
                        try:
                            _, writer = await asyncio.wait_for(
                                asyncio.open_connection(host, port),
                                timeout=5  # 添加连接超时
                            )
                            writer.close()
                            await writer.wait_closed()
                            ipList.append(host)
                        except Exception:
                            pass  # 静默处理连接失败
            else:
                # 减少重试次数从 3 次到 1 次，提升速度
                ipList = await self.__resolve(dnsresolver, host)

            return domain, ipList

    def __generateBlackList(self, blackList):
        logger.info("generate black list...")
        try:
            if os.path.exists(self.__blacklistFile):
                os.remove(self.__blacklistFile)
            
            with open(self.__blacklistFile, "w") as f:
                f.write('\n'.join(blackList) + '\n')
            logger.info("block domain: %d"%(len(blackList)))
        except Exception as e:
            logger.error("%s"%(e))
    
    def __generateChinaList(self, ChinaList):
        logger.info("generate China list...")
        try:
            if os.path.exists(self.__ChinalistFile):
                os.remove(self.__ChinalistFile)
            
            with open(self.__ChinalistFile, "w") as f:
                f.write('\n'.join(ChinaList) + '\n')
            logger.info("China domain: %d"%(len(ChinaList)))
        except Exception as e:
            logger.error("%s"%(e))

    def __testDomain(self, domainList, nameservers, port=53):
        logger.info("resolve domain...")
        # 配置 DNS 解析器
        dnsresolver = DNSResolver()
        dnsresolver.nameservers = nameservers
        dnsresolver.port = port
        dnsresolver.lifetime = 5  # DNS 查询超时时间（秒）
        
        # 启动异步循环
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        semaphore = asyncio.Semaphore(self.__maxTask)
        
        # 添加异步任务
        taskList = []
        for domain in domainList:
            task = asyncio.ensure_future(self.__pingx(dnsresolver, domain, semaphore))
            taskList.append(task)
        
        # 等待异步任务结束
        loop.run_until_complete(asyncio.gather(*taskList, return_exceptions=True))
        
        # 获取异步任务结果
        domainDict = {}
        for task in taskList:
            try:
                domain, ipList = task.result()
                domainDict[domain] = ipList
            except Exception:
                pass
        
        loop.close()
        logger.info("resolve domain: %d"%(len(domainDict)))
        return domainDict

    def __isChinaDomain(self, domain, ipList, fullSet_CN, domainSet_CN, compiled_regexps, keywordSet_CN, IPTrie_CN):
        """判断域名是否属于中国，使用预编译正则和前缀树进行高效判定"""
        isChinaDomain = False
        try:
            if ':' in domain:
                domain = domain[:domain.find(':')]
            
            # .cn 域名直接判定为中国
            if domain.endswith('.cn'):
                return domain, True
            
            # full: 完全匹配
            if domain in fullSet_CN:
                return domain, True
            
            # domain: 主域名匹配
            try:
                res = get_tld(domain, fix_protocol=True, as_object=True)
                if res.fld in domainSet_CN:
                    return domain, True
            except Exception:
                pass
            
            # regexp: 使用预编译正则
            for pattern in compiled_regexps:
                if pattern.search(domain):
                    return domain, True
            
            # keyword: 使用 in 操作符替代正则
            for keyword in keywordSet_CN:
                if keyword in domain:
                    return domain, True
            
            # IP 归属判定：使用前缀树 O(32) 时间复杂度
            for ip in ipList:
                if ip in IPTrie_CN:
                    return domain, True
                    
        except Exception as e: 
            logger.error('"%s": not domain'%(domain))
        
        return domain, isChinaDomain

    def generate(self):
        try:
            domainList = self.__getDomainList()
            if len(domainList) < 1:
                return
            
            domainDict = self.__testDomain(domainList, ["127.0.0.1"], 5053)

            fullSet_CN, domainSet_CN, regexpSet_CN, keywordSet_CN = self.__getDomainSet_CN()
            IPTrie_CN = self.__getIPTrie_CN()
            
            # 预编译所有正则表达式，避免重复编译
            compiled_regexps = [re.compile(pattern) for pattern in regexpSet_CN]
            logger.info("Compiled %d regexp patterns" % len(compiled_regexps))
            
            blackList = []
            if len(domainSet_CN) > 100 and len(IPTrie_CN) > 100:
                # 增大线程池规模
                max_workers = max(os.cpu_count() * 4, 16)
                thread_pool = ThreadPoolExecutor(max_workers=max_workers)
                logger.info("Using thread pool with %d workers" % max_workers)
                
                taskList = []
                for domain in domainList:
                    if domain in domainDict and domainDict[domain]:
                        taskList.append(thread_pool.submit(
                            self.__isChinaDomain, domain, domainDict[domain], 
                            fullSet_CN, domainSet_CN, compiled_regexps, keywordSet_CN, IPTrie_CN
                        ))
                    else:
                        blackList.append(domain)
                
                # 获取解析结果
                ChinaSet_tmp = set()
                for future in as_completed(taskList):
                    try:
                        domain, isChinaDomain = future.result()
                        if isChinaDomain:
                            ChinaSet_tmp.add(domain)
                    except Exception:
                        pass
                
                thread_pool.shutdown(wait=False)
                
                # 生成China域名列表
                ChinaList = [domain for domain in domainList if domain in ChinaSet_tmp]
                if ChinaList:
                    self.__generateChinaList(ChinaList)
            else:
                for domain in domainList:
                    if domain not in domainDict or not domainDict[domain]:
                        blackList.append(domain)

            # 生成黑名单
            if blackList:
                self.__generateBlackList(blackList)
        except Exception as e:
            logger.error("%s"%(e))

if __name__ == "__main__":
    blackList = BlackList()
    blackList.generate()