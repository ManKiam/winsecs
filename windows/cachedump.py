# -*- coding: utf-8 -*-
import platform


class Cachedump:
    def run(self, profile):
        pass
        # is_vista_or_higher = False
        # if float('.'.join(platform.version().split('.')[:2])) >= 6.0:
        #     is_vista_or_higher = True

        # mscache = dump_file_hashes(profile['system'], profile['security'], is_vista_or_higher)
        # if mscache:
        #     return ['__MSCache__', mscache]


modules = {"Cachedump": Cachedump()}
