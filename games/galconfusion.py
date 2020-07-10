# -*- coding: utf-8 -*-

import os

from winsecs.utils import OpenKey, winreg, log


class GalconFusion:
    def run(self):
        creds = []
        results = None

        # Find the location of steam - to make it easier we're going to use a try block
        # 'cos I'm lazy
        try:
            with OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Valve\\Steam') as key:
                results = winreg.QueryValueEx(key, 'SteamPath')
        except Exception:
            pass

        if not results:
            return

        steampath = results[0]
        userdata = os.path.join(steampath, 'userdata')

        # Check that we have a userdata directory
        if not os.path.exists(userdata):
            log.error('Steam doesn\'t have a userdata directory.')
            return

        # Now look for Galcon Fusion in every user
        for f in os.listdir(userdata):
            filepath = os.path.join(userdata, f, '44200\\remote\\galcon.cfg')
            if not os.path.exists(filepath):
                continue

            # If we're here we should have a Galcon Fusion file
            with open(filepath, mode='rb') as cfgfile:
                # We've found a config file, now extract the creds
                data = cfgfile.read()
                creds.append({'Login': data[4:0x23], 'Password': data[0x24:0x43]})

        return creds


modules = {"GalconFusion": GalconFusion()}
