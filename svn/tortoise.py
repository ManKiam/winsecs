# -*- coding: utf-8 -*-
import base64
import os

from winsecs.utils import CryptUnprotectData


class Tortoise:
    def run(self, profile):
        pwd_found = []
        path = os.path.join(profile["APPDATA"], 'Subversion\\auth\\svn.simple')
        if not os.path.isfile(path):
            return

        for root, dirs, files in os.walk(path + os.sep):
            for filename in files:
                f = open(os.path.join(path, filename), 'r')
                url = ''
                username = ''
                result = ''

                i = 0
                # password
                for line in f:
                    if i == -1:
                        result = line.replace('\n', '')
                        break
                    if line.startswith('password'):
                        i = -3
                    i += 1

                i = 0
                # url
                for line in f:
                    if i == -1:
                        url = line.replace('\n', '')
                        break
                    if line.startswith('svn:realmstring'):
                        i = -3
                    i += 1

                i = 0

                # username
                for line in f:
                    if i == -1:
                        username = line.replace('\n', '')
                        break
                    if line.startswith('username'):
                        i = -3
                    i += 1

                # encrypted the password
                if result:
                    try:
                        password_bytes = CryptUnprotectData(base64.b64decode(result), profile)
                        pwd_found.append({
                            'URL': url,
                            'Login': username,
                            'Password': password_bytes.decode("utf-8")
                        })
                    except Exception:
                        pass
        return pwd_found


modules = {"Tortoise": Tortoise()}
