# -*- coding: utf-8 -*-
import os
from xml.etree.cElementTree import ElementTree


class Squirrel:
    def run(self, profile):
        path = os.path.join(profile['USERPROFILE'], '.squirrel-sql', 'SQLAliases23.xml')
        if not os.path.exists(path):
            return

        tree = ElementTree(file=path)
        pwd_found = []
        elements = {'name': 'Name', 'url': 'URL', 'userName': 'Login', 'password': 'Password'}
        for elem in tree.iter('Bean'):
            values = {}
            for e in elem:
                if e.tag in elements:
                    values[elements[e.tag]] = e.text
            if values:
                pwd_found.append(values)

        return pwd_found


modules = {"Squirrel": Squirrel()}
