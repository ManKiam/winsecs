# -*- coding: utf-8 -*-
import array
import base64
import binascii
import hashlib
import os
import re
from xml.etree.cElementTree import ElementTree
from winsecs.utils import log

from Crypto.Cipher import DES3


class SQLDeveloper:
    def decrypt(self, msg, _passphrase):
        salt = array.array('b', [5, 19, -103, 66, -109, 114, -24, -83])
        hexsalt = binascii.hexlify(salt)

        key = bytearray(_passphrase, encoding="utf-8") + binascii.unhexlify(hexsalt)
        for i in range(42):
            m = hashlib.md5(key)
            key = m.digest()
        dk, iv = key[:8], key[8:]

        enc_text = base64.b64decode(msg)
        text = DES3.new(dk, DES3.MODE_CBC, iv).decrypt(enc_text)
        return re.sub(rb'[\x01-\x08]', '', text)

    def get_passphrase(self, path):
        xml_name = 'product-preferences.xml'
        xml_file = None

        if os.path.exists(os.path.join(path, xml_name)):
            xml_file = os.path.join(path, xml_name)
        else:
            for p in os.listdir(path):
                if p.startswith('system'):
                    new_directory = os.path.join(path, p)

                    for pp in os.listdir(new_directory):
                        if pp.startswith('o.sqldeveloper'):
                            if os.path.exists(os.path.join(new_directory, pp, xml_name)):
                                xml_file = os.path.join(new_directory, pp, xml_name)
                            break
        if xml_file:
            tree = ElementTree(file=xml_file)
            for elem in tree.iter():
                if 'n' in elem.attrib.keys():
                    if elem.attrib['n'] == 'db.system.id':
                        return elem.attrib['v']

    def run(self, profile):
        path = os.path.join(profile['APPDATA'], 'SQL Developer')
        if not os.path.exists(path):
            return

        _passphrase = self.get_passphrase(path)
        if not self._passphrase:
            return

        log.debug('Passphrase found: {passphrase}'.format(passphrase=_passphrase))
        xml_name = 'connections.xml'
        xml_file = None

        if os.path.exists(os.path.join(path, xml_name)):
            xml_file = os.path.join(path, xml_name)
        else:
            for p in os.listdir(path):
                if p.startswith('system'):
                    new_directory = os.path.join(path, p)

                    for pp in os.listdir(new_directory):
                        if pp.startswith('o.jdeveloper.db.connection'):
                            if os.path.exists(os.path.join(new_directory, pp, xml_name)):
                                xml_file = os.path.join(new_directory, pp, xml_name)
                            break

        if xml_file:
            renamed_value = {'sid': 'SID', 'port': 'Port', 'hostname': 'Host', 'user': 'Login',
                                'password': 'Password', 'ConnName': 'Name', 'customUrl': 'URL',
                                'SavePassword': 'SavePassword', 'driver': 'Driver'}
            tree = ElementTree(file=xml_file)

            pwd_found = []
            for e in tree.findall('Reference'):
                values = {}
                for ee in e.findall('RefAddresses/StringRefAddr'):
                    if ee.attrib['addrType'] in renamed_value and ee.find('Contents').text is not None:
                        name = renamed_value[ee.attrib['addrType']]
                        value = ee.find('Contents').text if name != 'Password' else self.decrypt(ee.find('Contents').text, _passphrase)
                        values[name] = value

                pwd_found.append(values)

            return pwd_found


modules = {"SQLDeveloper": SQLDeveloper()}
