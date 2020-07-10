# -*- coding: utf-8 -*-
import array
import base64
import binascii
import hashlib
import os
import re
from xml.etree.cElementTree import ElementTree

from Crypto.Cipher import DES3


class Dbvisualizer:
    def decrypt(self, msg):
        salt = array.array('b', [-114, 18, 57, -100, 7, 114, 111, 90])
        hexsalt = binascii.hexlify(salt)

        key = bytearray('qinda', encoding="utf-8") + binascii.unhexlify(hexsalt)
        for i in range(10):
            m = hashlib.md5(key)
            key = m.digest()
        dk, iv = key[:8], key[8:]

        enc_text = base64.b64decode(msg)
        text = DES3.new(dk, DES3.MODE_CBC, iv).decrypt(enc_text)
        return re.sub(rb'[\x01-\x08]', '', text)

    def run(self, profile):
        path = os.path.join(profile['USERPROFILE'], '.dbvis', 'config70', 'dbvis.xml')
        if not os.path.isfile(path):
            return

        tree = ElementTree(file=path)

        pwd_found = set()
        elements = {'Alias': 'Name', 'Userid': 'Login', 'Password': 'Password', 'UrlVariables//Driver': 'Driver'}

        for e in tree.findall('Databases/Database'):
            values = {}
            for elem in elements:
                try:
                    if elem != "Password":
                        values[elements[elem]] = e.find(elem).text
                    else:
                        values[elements[elem]] = self.decrypt(e.find(elem).text)
                except Exception:
                    pass

            try:
                elem = e.find('UrlVariables')
                for ee in elem.getchildren():
                    for ele in ee.getchildren():
                        if 'Server' == ele.attrib['UrlVariableName']:
                            values['Host'] = str(ele.text)
                        if 'Port' == ele.attrib['UrlVariableName']:
                            values['Port'] = str(ele.text)
                        if 'SID' == ele.attrib['UrlVariableName']:
                            values['SID'] = str(ele.text)
            except Exception:
                pass

            if values:
                pwd_found.add(list(values.values()))

        return list(pwd_found)


modules = {"Dbvisualizer": Dbvisualizer()}
