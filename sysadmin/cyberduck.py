# -*- coding: utf-8 -*-
import base64
import os
from xml.etree.cElementTree import ElementTree

from winsecs.utils import log, CryptUnprotectData



class Cyberduck:
    # find the user.config file containing passwords
    def get_application_path(self, directory):
        if os.path.exists(directory):
            for dr in os.listdir(directory):
                if dr.startswith('Cyberduck'):
                    for d in os.listdir(os.path.join(directory, dr)):
                        path = os.path.join(directory, dr, d, 'user.config')
                        return path

    def run(self, profile):
        xml_file = self.get_application_path(os.path.join(profile['APPDATA'], 'Cyberduck'))
        if xml_file and os.path.isfile(xml_file):
            tree = ElementTree(file=xml_file)

            pwd_found = []
            for elem in tree.iter():
                try:
                    if elem.attrib['name'].startswith('ftp') or elem.attrib['name'].startswith('ftps') \
                            or elem.attrib['name'].startswith('sftp') or elem.attrib['name'].startswith('http') \
                            or elem.attrib['name'].startswith('https'):
                        encrypted_password = base64.b64decode(elem.attrib['value'])
                        password_bytes = CryptUnprotectData(encrypted_password, profile)
                        pwd_found.append({
                            'URL': elem.attrib['name'],
                            'Password': password_bytes.decode("utf-8"),
                        })
                except Exception as e:
                    log.debug(str(e))

            return pwd_found


modules = {"Cyberduck": Cyberduck()}
