#!/usr/bin/env python
# -*- coding: utf-8 -*-
# portable decryption functions and BSD DB parsing by Laurent Clevy (@lorenzo2472)
# from https://github.com/lclevy/firepwd/blob/master/firepwd.py

import hmac
import json
import shutil
import sqlite3
import struct
import tempfile
import traceback
import os

from Crypto.Cipher import DES3, AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
from winsecs.dico import get_dic
from winsecs.utils import char_to_int, log
from pyasn1.codec.der import decoder
from binascii import unhexlify
from base64 import b64decode
from hashlib import sha1, pbkdf2_hmac

from configparser import RawConfigParser

CKA_ID = unhexlify('f8000000000000000000000000000001')


class Mozilla:
    def __init__(self, path):
        self.path = path

    def get_firefox_profiles(self, directory):
        """
        List all profiles
        """
        cp = RawConfigParser()
        profile_list = []

        if os.path.isfile(os.path.join(directory, 'profiles.ini')):
            try:
                cp.read(os.path.join(directory, 'profiles.ini'))
                for section in cp.sections():
                    if section.startswith('Profile') and cp.has_option(section, 'Path'):
                        profile_path = None

                        if cp.has_option(section, 'IsRelative'):
                            if cp.get(section, 'IsRelative') == '1':
                                profile_path = os.path.join(directory, cp.get(section, 'Path').strip())
                            elif cp.get(section, 'IsRelative') == '0':
                                profile_path = cp.get(section, 'Path').strip()

                        else:  # No "IsRelative" in profiles.ini
                            profile_path = os.path.join(directory, cp.get(section, 'Path').strip())

                        if profile_path:
                            profile_list.append(profile_path.replace('/', '\\'))

            except Exception as e:
                log.error(f'An error occurred while reading profiles.ini: {e}')

        else:
            for i in os.listdir(directory):
                i = os.path.join(directory, i, 'cookies.sqlite')
                if os.path.isfile(i):
                    profile_list.append(i)

        return list(set(profile_list))

    def get_key(self, profile):
        """
        Get main key used to encrypt all data (user / password).
        Depending on the Firefox version, could be stored in key3.db or key4.db file.
        """
        try:
            row = None
            # Remove error when file is empty
            with open(os.path.join(profile, 'key4.db'), 'rb') as f:
                content = f.read()

            if content:
                # Firefox 58.0.2 / NSS 3.35 with key4.db in SQLite
                conn = sqlite3.connect(os.path.join(profile, 'key4.db'))
                c = conn.cursor()
                # First check password
                c.execute(
                    "SELECT item1,item2 FROM metadata WHERE id = 'password';")
                try:
                    row = c.next()  # Python 2
                except Exception:
                    row = next(c)  # Python 3

        except Exception:
            log.debug(traceback.format_exc())

        else:
            if row:
                global_salt, master_password, entry_salt = self.manage_masterpassword(master_password=b'', key_data=row)

                if global_salt:
                    try:
                        # Decrypt 3DES key to decrypt "logins.json" content
                        c.execute("SELECT a11,a102 FROM nssPrivate;")
                        for row in c:
                            if row[0]:
                                break

                        a11 = row[0]  # CKA_VALUE
                        # f8000000000000000000000000000001, CKA_ID
                        a102 = row[1]

                        if a102 == CKA_ID:
                            # a11  : CKA_VALUE
                            # a102 : f8000000000000000000000000000001, CKA_ID
                            # self.print_asn1(a11, len(a11), 0)
                            # SEQUENCE {
                            #     SEQUENCE {
                            #         OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
                            #         SEQUENCE {
                            #             OCTETSTRING entry_salt_for_3des_key
                            #             INTEGER 01
                            #         }
                            #     }
                            #     OCTETSTRING encrypted_3des_key (with 8 bytes of PKCS#7 padding)
                            # }
                            decoded_a11 = decoder.decode(a11)
                            key = self.decrypt_3des(
                                decoded_a11, master_password, global_salt)
                            if key:
                                log.debug('key: {key}'.format(key=repr(key)))
                                yield key[:24]
                        # else:
                            # Nothing saved

                    except Exception:
                        log.debug(traceback.format_exc())

        try:
            key3_file = os.path.join(profile, 'key3.db')
            if os.path.exists(key3_file):
                key_data = self.read_bsddb(key3_file)
                # Check masterpassword
                global_salt, master_password, entry_salt = self.manage_masterpassword(master_password='', key_data=key_data, new_version=False)
                if global_salt:
                    key = self.extract_secret_key(key_data=key_data, global_salt=global_salt, master_password=master_password, entry_salt=entry_salt)
                    if key:
                        log.debug('key: {key}'.format(key=repr(key)))
                        yield key[:24]
        except Exception:
            log.debug(traceback.format_exc())

    @staticmethod
    def get_short_le(d, a):
        return struct.unpack('<H', d[a:a + 2])[0]

    @staticmethod
    def get_long_be(d, a):
        return struct.unpack('>L', d[a:a + 4])[0]

    def print_asn1(self, d, l, rl):
        """
        Used for debug
        """
        type_ = char_to_int(d[0])
        length = char_to_int(d[1])
        if length & 0x80 > 0:  # http://luca.ntop.org/Teaching/Appunti/asn1.html,
            # nByteLength = length & 0x7f
            length = char_to_int(d[2])
            # Long form. Two to 127 octets. Bit 8 of first octet has value "1" and
            # bits 7-1 give the number of additional length octets.
            skip = 1
        else:
            skip = 0

        if type_ == 0x30:
            seq_len = length
            read_len = 0
            while seq_len > 0:
                len2 = self.print_asn1(
                    d[2 + skip + read_len:], seq_len, rl + 1)
                seq_len = seq_len - len2
                read_len = read_len + len2
            return length + 2
        elif type_ in (0x6, 0x5, 0x4, 0x2):  # OID, OCTETSTRING, NULL, INTEGER
            return length + 2
        elif length == l - 2:
            self.print_asn1(d[2:], length, rl + 1)
            return length

    def read_bsddb(self, name):
        """
        Extract records from a BSD DB 1.85, hash mode
        Obsolete with Firefox 58.0.2 and NSS 3.35, as key4.db (SQLite) is used
        """
        with open(name, 'rb') as f:
            # http://download.oracle.com/berkeley-db/db.1.85.tar.gz
            header = f.read(4 * 15)
            magic = self.get_long_be(header, 0)
            if magic != 0x61561:
                log.warning('Bad magic number')
                return False

            version = self.get_long_be(header, 4)
            if version != 2:
                log.warning('Bad version !=2 (1.85)')
                return False

            pagesize = self.get_long_be(header, 12)
            nkeys = self.get_long_be(header, 0x38)
            readkeys = 0
            page = 1
            db1 = []

            while readkeys < nkeys:
                f.seek(pagesize * page)
                offsets = f.read((nkeys + 1) * 4 + 2)
                offset_vals = []
                i = 0
                nval = 0
                val = 1
                keys = 0

                while nval != val:
                    keys += 1
                    key = self.get_short_le(offsets, 2 + i)
                    val = self.get_short_le(offsets, 4 + i)
                    nval = self.get_short_le(offsets, 8 + i)
                    offset_vals.append(key + pagesize * page)
                    offset_vals.append(val + pagesize * page)
                    readkeys += 1
                    i += 4

                offset_vals.append(pagesize * (page + 1))
                val_key = sorted(offset_vals)
                for i in range(keys * 2):
                    f.seek(val_key[i])
                    data = f.read(val_key[i + 1] - val_key[i])
                    db1.append(data)
                page += 1

        db = {}
        for i in range(0, len(db1), 2):
            db[db1[i + 1]] = db1[i]

        return db

    @staticmethod
    def decrypt_3des(decoded_item, master_password, global_salt):
        """
        User master key is also encrypted (if provided, the master_password could be used to encrypt it)
        """
        # See http://www.drh-consultancy.demon.co.uk/key3.html
        pbeAlgo = str(decoded_item[0][0][0])
        if pbeAlgo == '1.2.840.113549.1.12.5.1.3':  # pbeWithSha1AndTripleDES-CBC
            entry_salt = decoded_item[0][0][1][0].asOctets()
            cipher_t = decoded_item[0][1].asOctets()

            # See http://www.drh-consultancy.demon.co.uk/key3.html
            hp = sha1(global_salt + master_password).digest()
            pes = entry_salt + b'\x00' * (20 - len(entry_salt))
            chp = sha1(hp + entry_salt).digest()
            k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
            tk = hmac.new(chp, pes, sha1).digest()
            k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
            k = k1 + k2
            iv = k[-8:]
            key = k[:24]
            return DES3.new(key, DES3.MODE_CBC, iv).decrypt(cipher_t)

        # New version
        elif pbeAlgo == '1.2.840.113549.1.5.13':  # pkcs5 pbes2

            assert str(decoded_item[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
            assert str(decoded_item[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
            assert str(decoded_item[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
            # https://tools.ietf.org/html/rfc8018#page-23
            entry_salt = decoded_item[0][0][1][0][1][0].asOctets()
            iteration_count = int(decoded_item[0][0][1][0][1][1])
            key_length = int(decoded_item[0][0][1][0][1][2])
            assert key_length == 32

            k = sha1(global_salt + master_password).digest()
            key = pbkdf2_hmac('sha256', k, entry_salt, iteration_count, dklen=key_length)

            # https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
            iv = b'\x04\x0e' + decoded_item[0][0][1][1][1].asOctets()
            # 04 is OCTETSTRING, 0x0e is length == 14
            encrypted_value = decoded_item[0][1].asOctets()
            cleartxt = AES.new(key, AES.MODE_CBC, iv).decrypt(encrypted_value)

            return cleartxt

    def extract_secret_key(self, key_data, global_salt, master_password, entry_salt):

        if CKA_ID not in key_data:
            return None

        priv_key_entry = key_data[CKA_ID]
        salt_len = char_to_int(priv_key_entry[1])
        name_len = char_to_int(priv_key_entry[2])
        priv_key_entry_asn1 = decoder.decode(priv_key_entry[3 + salt_len + name_len:])
        # data = priv_key_entry[3 + salt_len + name_len:]
        # self.print_asn1(data, len(data), 0)

        # See https://github.com/philsmd/pswRecovery4Moz/blob/master/pswRecovery4Moz.txt
        priv_key = self.decrypt_3des(priv_key_entry_asn1, master_password, global_salt)
        # self.print_asn1(priv_key, len(priv_key), 0)
        priv_key_asn1 = decoder.decode(priv_key)
        pr_key = priv_key_asn1[0][2].asOctets()
        # self.print_asn1(pr_key, len(pr_key), 0)
        pr_key_asn1 = decoder.decode(pr_key)
        # id = pr_key_asn1[0][1]
        key = long_to_bytes(pr_key_asn1[0][3])
        return key

    @staticmethod
    def decode_login_data(data):
        # First base64 decoding, then ASN1DERdecode
        asn1data = decoder.decode(b64decode(data))
        # For login and password, keep :(key_id, iv, ciphertext)
        return asn1data[0][0].asOctets(), asn1data[0][1][1].asOctets(), asn1data[0][2].asOctets()

    def get_login_data(self, prof):
        """
        Get encrypted data (user / password) and host from the json or sqlite files
        """
        logins = []
        try:
            conn = sqlite3.connect(os.path.join(prof, 'signons.sqlite'))
            c = conn.cursor()
            c.execute('SELECT * FROM moz_logins;')
            # Using sqlite3 database
            for row in c:
                enc_username = row[6]
                enc_password = row[7]
                logins.append((self.decode_login_data(enc_username), self.decode_login_data(enc_password), row[1]))
            conn.close()
        except sqlite3.OperationalError:  # Since Firefox 32, json is used instead of sqlite3
            try:
                for row in json.load(open(os.path.join(prof, 'logins.json')))['logins']:
                    enc_username = row['encryptedUsername']
                    enc_password = row['encryptedPassword']
                    logins.append((
                        self.decode_login_data(enc_username),
                        self.decode_login_data(enc_password),
                        row['hostname']
                    ))
            except Exception:
                log.debug(traceback.format_exc())

        return logins

    def manage_masterpassword(self, master_password=b'', key_data=None, new_version=True):
        """
        Check if a master password is set.
        If so, try to find it using a dictionary attack
        """
        global_salt, master_password, entry_salt = self.is_master_password_correct(master_password=master_password, key_data=key_data, new_version=new_version)

        if not global_salt:
            log.info('Master Password is used !')
            global_salt, master_password, entry_salt = self.brute_master_password(key_data=key_data, new_version=new_version)
            if not master_password:
                return '', '', ''

        return global_salt, master_password, entry_salt

    def is_master_password_correct(self, key_data, master_password=b'', new_version=True):
        try:
            entry_salt = b""
            if not new_version:
                # See http://www.drh-consultancy.demon.co.uk/key3.html
                pwd_check = key_data.get(b'password-check')
                if not pwd_check:
                    return '', '', ''
                # Hope not breaking something (not tested for old version)
                # entry_salt_len = char_to_int(pwd_check[1])
                # entry_salt = pwd_check[3: 3 + entry_salt_len]
                # encrypted_passwd = pwd_check[-16:]
                global_salt = key_data[b'global-salt']

            else:
                global_salt = key_data[0]  # Item1
                item2 = key_data[1]
                # self.print_asn1(item2, len(item2), 0)
                # SEQUENCE {
                # 	SEQUENCE {
                # 		OBJECTIDENTIFIER 1.2.840.113549.1.12.5.1.3
                # 		SEQUENCE {
                # 			OCTETSTRING entry_salt_for_passwd_check
                # 			INTEGER 01
                # 		}
                # 	}
                # 	OCTETSTRING encrypted_password_check
                # }
                decoded_item2 = decoder.decode(item2)

            cleartext_data = self.decrypt_3des(decoded_item2, master_password, global_salt)
            if cleartext_data != b'password-check\x02\x02':
                return '', '', ''

            return global_salt, master_password, entry_salt
        except Exception:
            log.debug(traceback.format_exc())
            return '', '', ''

    def brute_master_password(self, key_data, new_version=True):
        """
        Try to find master_password doing a dictionary attack using the 500 most used passwords
        """
        wordlist = get_dic()
        num_lines = (len(wordlist) - 1)
        log.info('%d most used passwords !!! ' % num_lines)

        for word in wordlist:
            global_salt, master_password, entry_salt = self.is_master_password_correct(key_data=key_data, master_password=word.strip(), new_version=new_version)
            if master_password:
                log.info('Master password found: {}'.format(master_password))
                return global_salt, master_password, entry_salt

        log.warning('No password has been found using the default list')
        return '', '', ''

    def run(self, profile):
        """
        Main function
        """
        credentials = {}
        cookies = []
        path = self.path.format(**profile)
        if not os.path.exists(path):
            return []

        for prof in self.get_firefox_profiles(path):
            log.debug(f'Profile path found: {prof}')

            creds = self.get_login_data(prof)
            if not creds:
                log.info('Database empty')
                continue

            pwd_found = []
            for key in self.get_key(prof):
                for user, passw, url in creds:
                    try:
                        pwd_found.append([
                            url,
                            unpad(DES3.new(key, DES3.MODE_CBC, user[1]).decrypt(user[2]), 8).decode(),
                            unpad(DES3.new(key, DES3.MODE_CBC, passw[1]).decrypt(passw[2]), 8).decode()
                        ])
                    except Exception:
                        log.debug('An error occured decrypting the password: {error}'.format(error=traceback.format_exc()))
            if pwd_found:
                credentials[prof] = pwd_found

            cookie = os.path.join(prof, 'cookies.sqlite')
            if os.path.isfile(cookie):
                cookies.append(cookie)

        ret = {}
        if cookies:
            ret['Cookies'] = cookies
        if credentials:
            ret['Credentials'] = credentials
        return ret


# Name: path
browsers_address = {
    'firefox': '{APPDATA}\\Mozilla\\Firefox',
    'blackHawk': '{APPDATA}\\NETGATE Technologies\\BlackHawk',
    'cyberfox': '{APPDATA}\\8pecxstudios\\Cyberfox',
    'comodo IceDragon': '{APPDATA}\\Comodo\\IceDragon',
    'k-Meleon': '{APPDATA}\\K-Meleon',
    'waterfox': '{APPDATA}\\Waterfox',
    'icecat': '{APPDATA}\\Mozilla\\icecat',
}

modules = {i: Mozilla(browsers_address[i]) for i in browsers_address}
