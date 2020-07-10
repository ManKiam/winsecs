# -*- coding: utf-8 -*-
import base64
import os

from winsecs.utils import char_to_int

from configparser import ConfigParser


class KalypsoMedia:
    def xorstring(self, s, k):
        """
        xors the two strings
        """
        return b''.join(bytes([char_to_int(x) ^ char_to_int(y)]) for x, y in zip(s, k))

    def run(self, profile):
        creds = []
        key = b'lwSDFSG34WE8znDSmvtwGSDF438nvtzVnt4IUv89'
        inifile = os.path.join(profile['APPDATA'], 'Kalypso Media\\Launcher\\launcher.ini')

        # The actual user details are stored in *.userdata files
        if os.path.exists(inifile):
            config = ConfigParser()
            config.read(inifile)

            # get the encoded password
            cookedpw = base64.b64decode(config.get('styx user', 'password'))

            creds.append({
                'Login': config.get('styx user', 'login'),
                'Password': self.xorstring(cookedpw, key)
            })
            return creds


modules = {"KalypsoMedia": KalypsoMedia()}
