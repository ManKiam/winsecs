# -*- coding: utf-8 -*-
import base64
import json
import os
import shutil
import sqlite3
import win32crypt
import tempfile
import traceback

from Crypto.Cipher import AES

from winsecs.utils import log


class Chromium:
    def __init__(self, paths):
        self.paths = paths if isinstance(paths, list) else [paths]

    def db_dirs(self, profile):
        """
        Return database directories for all profiles within all paths
        """
        databases = set()
        for path in self.paths:
            path = path.format(**profile)

            profiles_path = os.path.join(path, 'Local State')
            if not os.path.isfile(profiles_path):
                continue

            master_key = None
            # List all users profile (empty string means current dir, without a profile)
            profiles = {'Default', ''}

            # Automatic join all other additional profiles
            for dirs in os.listdir(path):
                if os.path.isdir(os.path.join(path, dirs)) and dirs.startswith('Profile'):
                    profiles.add(dirs)

            with open(profiles_path) as f:
                try:
                    data = json.load(f)
                    # Add profiles from json to Default profile. set removes duplicates
                    profiles |= set(data['profile']['info_cache'])
                except Exception:
                    pass

            with open(profiles_path) as f:
                try:
                    master_key = base64.b64decode(json.load(f)["os_crypt"]["encrypted_key"])[5:]  # removing DPAPI
                    master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
                except Exception:
                    master_key = None

            # Each profile has its own password database
            for profile in profiles:
                # Some browsers use names other than "Login Data"
                # Like YandexBrowser - "Ya Login Data", UC Browser - "UC Login Data.18"
                try:
                    db_files = os.listdir(os.path.join(path, profile))
                except Exception:
                    continue
                for db in db_files:
                    if db.lower() in ['login data', 'ya passman data']:
                        databases.add((os.path.join(path, profile, db), master_key))
        return list(databases)

    def maketmp(self):
        """
        Copying db will bypass lock errors
        Using user tempfile will produce an error when impersonating users (Permission denied)
        A public directory should be used if this error occured (e.g C:\\Users\\Public)
        """
        root_dir = [tempfile.gettempdir(), os.environ.get('PUBLIC', None), os.environ.get('SystemDrive', None)]
        for r in root_dir:
            try:
                return tempfile.TemporaryFile(dir=r, delete=False).name
            except Exception:
                log.debug(traceback.format_exc())

    def creds_dump(self, db_path, is_yandex=False, master_key=None):
        """
        Export credentials from the given database

        :param unicode db_path: database path
        :return: list of credentials
        :rtype: tuple
        """
        credentials = set()
        # yandex_enckey = None

        # if is_yandex:
        #     try:
        #         credman_passwords = Credman().run()
        #         for credman_password in credman_passwords:
        #             if b'Yandex' in credman_password.get('URL', b''):
        #                 if credman_password.get('Password'):
        #                     yandex_enckey = credman_password.get('Password')
        #                     log.info(f'EncKey found: {yandex_enckey!r}')
        #         assert yandex_enckey
        #     except Exception:
        #         log.debug(traceback.format_exc())
        #         # Passwords could not be decrypted without encKey
        #         log.info('EncKey has not been retrieved')
        #         return []

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        except Exception:
            log.debug(traceback.format_exc())
            return list(credentials)

        for url, login, password in cursor.fetchall():
            try:
                # Yandex passwords use a masterkey stored on windows credential manager
                # https://yandex.com/support/browser-passwords-crypto/without-master.html
                if is_yandex:
                    try:
                        try:
                            p = json.loads(str(password))
                        except Exception:
                            p = json.loads(password)

                        password = base64.b64decode(p['p'])
                    except Exception:
                        # New version does not use json format
                        pass

                    # Passwords are stored using AES-256-GCM algorithm
                    # The key used to encrypt is stored on the credential manager

                    # yandex_enckey:
                    #   - 4 bytes should be removed to be 256 bits
                    #   - these 4 bytes correspond to the nonce ?

                    # cipher = AES.new(yandex_enckey, AES.MODE_GCM)
                    # plaintext = cipher.decrypt(password)
                    # Failed...
                else:
                    # Decrypt the Password
                    try:
                        password_bytes = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
                    except:
                        try:
                            password_bytes = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
                        except:
                            password_bytes = None

                    if password_bytes is not None:
                        password = password_bytes.decode()
                    elif master_key:
                        # chromium version > 80
                        try:
                            iv = password[3:15]
                            payload = password[15:]
                            cipher = AES.new(master_key, AES.MODE_GCM, iv)
                            password = cipher.decrypt(payload)[:-16].decode()  # remove suffix bytes
                        except:
                            pass

                if not url and not login and not password:
                    continue

                credentials.add((url, login, password))
            except Exception:
                log.debug(traceback.format_exc())

        conn.close()
        return list(credentials)

    def run(self, profile):
        credentials = {}
        databases = self.db_dirs(profile)

        for database_path, master_key in databases:

            log.debug('Database found: {db}'.format(db=database_path))

            # Copy database before to query it (bypass lock errors)
            temp = self.maketmp()
            shutil.copy(database_path, temp)
            log.debug(f'Temporary db copied: {temp}')
            try:
                found = self.creds_dump(temp, ('yandex' in database_path.lower()), master_key)
                if found:
                    credentials[database_path] = found
                os.remove(temp)
            except Exception:
                log.debug(traceback.format_exc())

        return credentials


class UCBrowser(Chromium):
    def __init__(self):
        pass

    def db_dirs(self, profile):
        uc = '{LOCALAPPDATA}\\UCBrowser'
        try:
            # UC Browser seems to have random characters appended to the User Data dir so we'll list them all
            self.paths = [os.path.join(uc, d) for d in os.listdir(uc.format(**profile))]
        except Exception:
            self.paths = []
        return Chromium.db_dirs(self, profile)


browsers_address = {
    '7Star': '{LOCALAPPDATA}\\7Star\\7Star\\User Data',
    'amigo': '{LOCALAPPDATA}\\Amigo\\User Data',
    'brave': '{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data',
    'centbrowser': '{LOCALAPPDATA}\\CentBrowser\\User Data',
    'chedot': '{LOCALAPPDATA}\\Chedot\\User Data',
    'chrome canary': '{LOCALAPPDATA}\\Google\\Chrome SxS\\User Data',
    'chromium': '{LOCALAPPDATA}\\Chromium\\User Data',
    'coccoc': '{LOCALAPPDATA}\\CocCoc\\Browser\\User Data',
    # Comodo IceDragon is Firefox-based
    'comodo dragon': '{LOCALAPPDATA}\\Comodo\\Dragon\\User Data',
    'elements browser': '{LOCALAPPDATA}\\Elements Browser\\User Data',
    'epic privacy browser': '{LOCALAPPDATA}\\Epic Privacy Browser\\User Data',
    'google chrome': '{LOCALAPPDATA}\\Google\\Chrome\\User Data',
    'kometa': '{LOCALAPPDATA}\\Kometa\\User Data',
    'opera': '{APPDATA}\\Opera Software\\Opera Stable',
    'orbitum': '{LOCALAPPDATA}\\Orbitum\\User Data',
    'sputnik': '{LOCALAPPDATA}\\Sputnik\\Sputnik\\User Data',
    'torch': '{LOCALAPPDATA}\\Torch\\User Data',
    'uran': '{LOCALAPPDATA}\\uCozMedia\\Uran\\User Data',
    'vivaldi': '{LOCALAPPDATA}\\Vivaldi\\User Data',
    'yandexBrowser': '{LOCALAPPDATA}\\Yandex\\YandexBrowser\\User Data',
    'microsoft edge': '{LOCALAPPDATA}\\Microsoft\\Edge\\User Data',
    'blisk': '{LOCALAPPDATA}\\Blisk\\User Data',
    'iron browser': '{LOCALAPPDATA}\\Iron Browser\\User Data',
    'ungoogled chromium': '{LOCALAPPDATA}\\Ungoogled Chromium\\User Data',
    'avast secure browser': '{LOCALAPPDATA}\\AVAST Software\\Browser\\User Data',
    'qihoo 360': '{LOCALAPPDATA}\\360Browser\\Browser\\User Data',
    'cryptotab browser': '{LOCALAPPDATA}\\CryptoTab Browser\\User Data'
}

modules = {i: Chromium(browsers_address[i]) for i in browsers_address}
modules["uc browser"] = UCBrowser()
