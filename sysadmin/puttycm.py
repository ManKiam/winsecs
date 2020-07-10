# -*- coding: utf-8 -*-
from xml.etree.cElementTree import ElementTree
from winsecs.utils import OpenKey, winreg

import os


class Puttycm:
    def get_default_database(self):
        try:
            key = OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\ACS\\PuTTY Connection Manager')
            db = winreg.QueryValueEx(key, 'DefaultDatabase')[0]
            winreg.CloseKey(key)
            return db
        except Exception:
            pass

    def run(self):
        database_path = self.get_default_database()
        if not database_path or not os.path.exists(database_path):
            return

        xml_file = os.path.expanduser(database_path)
        tree = ElementTree(file=xml_file)
        root = tree.getroot()

        pwd_found = []
        for connection in root.iter('connection'):
            children = connection.getchildren()
            values = {}
            for child in children:
                for c in child:
                    if str(c.tag) in ['name', 'protocol', 'host', 'port', 'description', 'login', 'password']:
                        values[str(c.tag).capitalize()] = str(c.text)

            if values:
                pwd_found.append(values)

        return pwd_found


modules = {"Puttycm": Puttycm()}
