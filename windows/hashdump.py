# -*- coding: utf-8 -*-


class Hashdump:
    def run(self):
        pass
        # hashdump = dump_file_hashes(constant.hives['system'], constant.hives['sam'])
        # if hashdump:
        #     pwd_found = ['__Hashdump__', hashdump]
        #     return pwd_found


modules = {"Hashdump": Hashdump()}
