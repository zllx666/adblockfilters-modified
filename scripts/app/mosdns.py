import os
from typing import List, Set, Dict

from loguru import logger

from app.base import APPBase


class MosDNS(APPBase):
    def __init__(self, blockList: List[str], unblockList: List[str], filterDict: Dict[str, str], filterList: List[str], filterList_var: List[str], ChinaSet: Set[str], fileName: str, sourceRule: str):
        super(MosDNS, self).__init__(blockList, unblockList, filterDict, filterList, filterList_var, ChinaSet, fileName, sourceRule)

    def _format_update_time(self) -> str:
        return self.time.replace("/", "-") + " UTC+8"

    def generate(self, isLite=False):
        try:
            if isLite:
                logger.info("generate adblock MosDNS v5 Lite...")
                fileName = self.fileNameLite
                blockList = self.blockListLite
            else:
                logger.info("generate adblock MosDNS v5...")
                fileName = self.fileName
                blockList = self.blockList

            if os.path.exists(fileName):
                os.remove(fileName)

            with open(fileName, "a") as f:
                f.write("#Title: AdBlock MosDNS v5\n")
                f.write("#--------------------------------------\n")
                f.write("#Total lines: %s\n" % (len(blockList)))
                f.write("#Version: %s\n" % (self.version))
                f.write("#Update time: %s\n" % (self._format_update_time()))
                if isLite:
                    f.write("#Update content: lite rules (China only).\n")
                else:
                    f.write("#Update content: auto update.\n")
                f.write("\n")
                f.write("#Homepage: %s\n" % (self.homepage))
                f.write("#License: %s/blob/main/LICENSE\n" % (self.homepage))
                f.write("\n\n")
                for domain in blockList:
                    f.write("full:%s\n" % (domain))

            if isLite:
                logger.info("adblock MosDNS v5 Lite: block=%d" % (len(blockList)))
            else:
                logger.info("adblock MosDNS v5: block=%d" % (len(blockList)))
        except Exception as e:
            logger.error("%s" % (e))
