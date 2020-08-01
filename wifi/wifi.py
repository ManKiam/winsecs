# -*- coding: utf-8 -*-
import os
import sys
import traceback

from xml.etree.cElementTree import ElementTree
from subprocess import Popen, PIPE

from winsecs.utils import log


class Wifi:
    def decrypt_using_lsa_secret(self, key):
        """
        Needs admin priv but will work with all systems
        """
        if constant.system_dpapi and constant.system_dpapi.unlocked:
            decrypted_blob = constant.system_dpapi.decrypt_wifi_blob(key)
            if decrypted_blob:
                try:
                    return decrypted_blob.decode(sys.getfilesystemencoding())
                except UnicodeDecodeError:
                    return str(decrypted_blob)

    def decrypt_using_netsh(self, ssid):
        """
        Does not need admin priv but would work only with english and french systems
        """

        language_keys = [b'key content', b'contenu de la cl', 'содержимое ключа'.encode('utf-8')]

        log.debug('Trying using netsh method')
        process = Popen(['netsh.exe', 'wlan', 'show', 'profile', str(ssid), 'key=clear'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        for st in stdout.split(b'\n'):
            if any(i in st.lower() for i in language_keys):
                password = st.split(b':')[1].strip()
                return password

    def run(self, profile):
        pass
        # interfaces_dir = os.path.join(profile['ALLUSERSPROFILE'], 'Microsoft\\Wlansvc\\Profiles\\Interfaces')

        # # for windows Vista or higher
        # mkfiles = profile.get('mkfiles')
        # if not os.path.isdir(interfaces_dir) or not mkfiles:
        #     return

        # pwd_found = []

        # for wifi_dir in os.listdir(interfaces_dir):
        #     repository = os.path.join(interfaces_dir, wifi_dir)
        #     if not os.path.isdir(repository):
        #         continue

        #     for file in os.listdir(repository):
        #         f = os.path.join(repository, file)
        #         if not os.path.isfile(f):
        #             continue
        #         values = {}
        #         tree = ElementTree(file=f)
        #         root = tree.getroot()
        #         xmlns = root.tag.split("}")[0] + '}'

        #         for elem in tree.iter():
        #             if elem.tag.endswith('SSID'):
        #                 for w in elem:
        #                     if w.tag == xmlns + 'name':
        #                         values['SSID'] = w.text

        #             if elem.tag.endswith('authentication'):
        #                 values['Authentication'] = elem.text

        #             if elem.tag.endswith('protected'):
        #                 values['Protected'] = elem.text

        #             if elem.tag.endswith('keyMaterial'):
        #                 key = elem.text
        #                 try:
        #                     password = self.decrypt_using_lsa_secret(key=key)
        #                     if not password:
        #                         password = self.decrypt_using_netsh(ssid=values['SSID'])
        #                     if password:
        #                         values['Password'] = password
        #                     else:
        #                         values['INFO'] = '[!] Password not found.'
        #                 except Exception:
        #                     log.error(traceback.format_exc())
        #                     values['INFO'] = '[!] Password not found.'

        #         if values and values.get('Authentication') != 'open':
        #             pwd_found.append(values)

        # return pwd_found


modules = {"Wifi": Wifi()}
