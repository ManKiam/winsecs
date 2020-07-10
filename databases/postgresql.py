# -*- coding: utf-8 -*-

import os


class PostgreSQL:
    def run(self, profile):
        path = os.path.join(profile['APPDATA'], 'postgresql', 'pgpass.conf')
        if not os.path.exists(path):
            return

        with open(path) as f:
            pwd_found = []
            for line in f.readlines():
                try:
                    items = line.strip().split(':')
                    pwd_found.append({
                        'Hostname': items[0],
                        'Port': items[1],
                        'DB': items[2],
                        'Username': items[3],
                        'Password': items[4]
                    })

                except Exception:
                    pass

            return pwd_found


modules = {"PostgreSQL": PostgreSQL()}
