# -*- coding: utf-8 -*-
import os
import sys
import traceback

from impacket.dpapi import DPAPI_BLOB
from xml.etree.cElementTree import ElementTree
from subprocess import Popen, PIPE
from binascii import unhexlify

from winsecs.utils import bin_to_string, log


class Wifi:
    def decrypt_using_lsa_secret(self, key_material, profile):
        """
        Needs admin priv but will work with all systems
        """
        if profile.get('sys32'):
            blob = DPAPI_BLOB(unhexlify(key_material))
            masterkey = profile['sys32'].get('user', {}).get(bin_to_string(blob['GuidMasterKey']).lower())
            if not masterkey:
                masterkey = profile['sys32'].get('machine', {}).get(bin_to_string(blob['GuidMasterKey']).lower())

            if masterkey:
                decrypted = blob.decrypt(unhexlify(masterkey))
                if decrypted:
                    decrypted = decrypted.rstrip(b'\0')
                    try:
                        return decrypted.decode(sys.getfilesystemencoding())
                    except UnicodeDecodeError:
                        return str(decrypted)

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
                return st.split(b':')[1].strip()

    def run(self, profile):
        interfaces_dir = os.path.join('C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces')

        # # for windows Vista or higher

        if not os.path.isdir(interfaces_dir):
            return

        pwd_found = []

        for wifi_dir in os.listdir(interfaces_dir):
            repository = os.path.join(interfaces_dir, wifi_dir)
            if not os.path.isdir(repository):
                continue

            for file in os.listdir(repository):
                f = os.path.join(repository, file)
                if not os.path.isfile(f):
                    continue
                values = {}
                tree = ElementTree(file=f)
                root = tree.getroot()
                xmlns = root.tag.split("}")[0] + '}'

                for elem in tree.iter():
                    if elem.tag.endswith('SSID'):
                        for w in elem:
                            if w.tag == xmlns + 'name':
                                values['SSID'] = w.text

                    if elem.tag.endswith('authentication'):
                        values['Authentication'] = elem.text

                    if elem.tag.endswith('protected'):
                        values['Protected'] = elem.text

                    if elem.tag.endswith('keyMaterial'):
                        try:
                            password = self.decrypt_using_lsa_secret(elem.text, profile)
                            if not password:
                                password = self.decrypt_using_netsh(ssid=values['SSID'])
                            if password:
                                values['Password'] = password
                            else:
                                values['INFO'] = '[!] Password not found.'
                        except Exception:
                            log.error(traceback.format_exc())
                            values['INFO'] = '[!] Password not found.'

                if values:
                    pwd_found.append(values)

        return pwd_found


modules = {"Wifi": Wifi()}
