# -*- coding: utf-8 -*-
import base64
import win32crypt

from xml.etree.cElementTree import ElementTree
from winsecs.utils import log

import os


class RDPManager:
    def decrypt_password(self, encrypted_password):
        try:
            decoded = base64.b64decode(encrypted_password)
            password_decrypted_bytes = win32crypt.CryptUnprotectData(decoded, None, None, None, 0)[1]
            password_decrypted = password_decrypted_bytes.decode("utf-8")
            password_decrypted = password_decrypted.replace('\x00', '')
        except Exception:
            password_decrypted = encrypted_password.replace('\x00', '')
        return password_decrypted

    def format_output_tag(self, tag):
        tag = tag.lower()
        if 'username' in tag:
            tag = 'Login'
        elif 'hostname' in tag:
            tag = 'URL'
        return tag.capitalize()

    def check_tag_content(self, values, c):
        if 'password' in c.tag.lower():
            values['Password'] = self.decrypt_password(c.text)
        else:
            tag = self.format_output_tag(c.tag)
            values[tag] = c.text
        return values

    def parse_element(self, root, element):
        pwd_found = []
        try:
            for r in root.findall(element):
                values = {}
                for child in r.getchildren():
                    if child.tag == 'properties':
                        for c in child.getchildren():
                            values = self.check_tag_content(values, c)
                    elif child.tag == 'logonCredentials':
                        for c in child.getchildren():
                            values = self.check_tag_content(values, c)
                    else:
                        values = self.check_tag_content(values, child)
                if values:
                    pwd_found.append(values)
        except Exception as e:
            log.debug(str(e))

        return pwd_found

    def run(self, profile):
        settings = [
            os.path.join(profile['LOCALAPPDATA'], 'Microsoft Corporation\\Remote Desktop Connection Manager\\RDCMan.settings'),
            os.path.join(profile['LOCALAPPDATA'], 'Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings')
        ]

        for setting in settings:
            if os.path.exists(setting):
                log.debug('Setting file found: {setting}'.format(setting=setting))

                tree = ElementTree(file=setting)
                root = tree.getroot()
                pwd_found = []

                elements = [
                    'CredentialsProfiles/credentialsProfiles/credentialsProfile',
                    'DefaultGroupSettings/defaultSettings/logonCredentials',
                    'file/server',
                ]

                for element in elements:
                    pwd_found += self.parse_element(root, element)

                try:
                    for r in root.find('FilesToOpen'):
                        if os.path.exists(r.text):
                            log.debug('New setting file found: %s' % r.text)
                            pwd_found += self.parse_xml(r.text)
                except Exception:
                    pass

                return pwd_found


modules = {"RDPManager": RDPManager()}
