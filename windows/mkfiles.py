import os
import traceback
import win32security

from Crypto.Hash import HMAC, SHA1, MD4
from hashlib import pbkdf2_hmac
from binascii import hexlify, unhexlify

from .lsa_secrets import LsaSecrets
from .registry_secrets import RegistrySecrets
from impacket.dpapi import MasterKeyFile, MasterKey, CredHist, DomainKey
from winsecs.utils import log


class MasterKeyFiles:
    def deriveKeysFromUser(self, sid, password):
        # Will generate two keys, one with SHA1 and another with MD4
        key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
        key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
        # For Protected users
        tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
        tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
        key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

        return key1, key2, key3

    def deriveKeysFromUserkey(self, sid, pwdhash):
        if len(pwdhash) == 20:
            # SHA1
            key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
            key2 = None
        else:
            # Assume MD4
            key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
            # For Protected users
            tmpKey = pbkdf2_hmac('sha256', pwdhash, sid.encode('utf-16le'), 10000)
            tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
            key2 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

        return key1, key2

    def decrypt(self, file, profile):
        data = open(file, 'rb').read()
        mkf = MasterKeyFile(data)
        data = data[len(mkf):]
        mk, bkmk, ch, dk = None, None, None, None

        if mkf['MasterKeyLen'] > 0:
            mk = MasterKey(data[:mkf['MasterKeyLen']])
            data = data[len(mk):]

        if mkf['BackupKeyLen'] > 0:
            bkmk = MasterKey(data[:mkf['BackupKeyLen']])
            data = data[len(bkmk):]

        if mkf['CredHistLen'] > 0:
            ch = CredHist(data[:mkf['CredHistLen']])
            data = data[len(ch):]

        if mkf['DomainKeyLen'] > 0:
            dk = DomainKey(data[:mkf['DomainKeyLen']])
            data = data[len(dk):]

        if self.dpapiSystem.get('NTHASH'):
            decryptedKey = mk.decrypt(self.dpapiSystem['NTHASH'])
            if decryptedKey:
                log.info('Decrypted key with key provided')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
        if self.dpapiSystem.get('SHAHASH'):
            decryptedKey = mk.decrypt(self.dpapiSystem['SHAHASH'])
            if decryptedKey:
                log.info('Decrypted key with key provided')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
        if self.dpapiSystem.get('NTHASH') and profile['SID']:
            key1, key2 = self.deriveKeysFromUserkey(profile['SID'], self.dpapiSystem['NTHASH'])
            decryptedKey = mk.decrypt(key1)
            if decryptedKey:
                log.info('Decrypted key with key provided + SID')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
            decryptedKey = mk.decrypt(key2)
            if decryptedKey:
                log.info('Decrypted key with key provided + SID')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
        if self.dpapiSystem.get('SHAHASH') and profile['SID']:
            key1, key2 = self.deriveKeysFromUserkey(profile['SID'], self.dpapiSystem['SHAHASH'])
            decryptedKey = mk.decrypt(key1)
            if decryptedKey:
                log.info('Decrypted key with key provided + SID')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
            decryptedKey = mk.decrypt(key2)
            if decryptedKey:
                log.info('Decrypted key with key provided + SID')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
        if self.dpapiSystem.get('UserKey') and self.dpapiSystem.get('MachineKey') and not profile['SID']:
            # We have hives, let's try to decrypt with them
            decryptedKey = mk.decrypt(self.dpapiSystem['UserKey'])
            if decryptedKey:
                log.info('Decrypted key with UserKey')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
            decryptedKey = mk.decrypt(self.dpapiSystem['MachineKey'])
            if decryptedKey:
                log.info('Decrypted key with MachineKey')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
            decryptedKey = bkmk.decrypt(self.dpapiSystem['UserKey'])
            if decryptedKey:
                log.info('Decrypted Backup key with UserKey')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
            decryptedKey = bkmk.decrypt(self.dpapiSystem['MachineKey'])
            if decryptedKey:
                log.info('Decrypted Backup key with MachineKey')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
        if self.dpapiSystem.get('UserKey') and self.dpapiSystem.get('MachineKey'):
            # Use SID + hash
            # We have hives, let's try to decrypt with them
            key1, key2 = self.deriveKeysFromUserkey(profile['SID'], self.dpapiSystem['UserKey'])
            decryptedKey = mk.decrypt(key1)
            if decryptedKey:
                log.info('Decrypted key with UserKey + SID')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
            decryptedKey = bkmk.decrypt(key1)
            if decryptedKey:
                log.info('Decrypted Backup key with UserKey + SID')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')
            if key2:
                decryptedKey = mk.decrypt(key2)
                if decryptedKey:
                    log.info('Decrypted key with UserKey + SID')
                    log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return hexlify(decryptedKey).decode('latin-1')
                decryptedKey = bkmk.decrypt(key2)
                if decryptedKey:
                    log.info('Decrypted Backup key with UserKey + SID')
                    log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return hexlify(decryptedKey).decode('latin-1')
        if self.dpapiSystem.get('PVK') and dk:
            pvkfile = open(self.dpapiSystem['PVK'], 'rb').read()
            key = PRIVATE_KEY_BLOB(pvkfile[len(PVK_FILE_HDR()):])
            private = privatekeyblob_to_pkcs1(key)
            cipher = PKCS1_v1_5.new(private)

            decryptedKey = cipher.decrypt(dk['SecretData'][::-1], None)
            if decryptedKey:
                domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey)
                key = domain_master_key['buffer'][:domain_master_key['cbMasterKey']]
                log.info('Decrypted key with domain backup key provided')
                log.info('Decrypted key: 0x%s' % hexlify(key).decode('latin-1'))
                return hexlify(key).decode('latin-1')
        if profile.get('password') and profile['SID']:
            key1, key2, key3 = self.deriveKeysFromUser(profile['SID'], profile['password'])

            # if mkf['flags'] & 4 ? SHA1 : MD4
            decryptedKey = mk.decrypt(key3)
            if decryptedKey:
                log.info('Decrypted key with User Key (MD4 protected)')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')

            decryptedKey = mk.decrypt(key2)
            if decryptedKey:
                log.info('Decrypted key with User Key (MD4)')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')

            decryptedKey = mk.decrypt(key1)
            if decryptedKey:
                log.info('Decrypted key with User Key (SHA1)')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')

            decryptedKey = bkmk.decrypt(key3)
            if decryptedKey:
                log.info('Decrypted Backup key with User Key (MD4 protected)')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')

            decryptedKey = bkmk.decrypt(key2)
            if decryptedKey:
                log.info('Decrypted Backup key with User Key (MD4)')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')

            decryptedKey = bkmk.decrypt(key1)
            if decryptedKey:
                log.info('Decrypted Backup key with User Key (SHA1)')
                log.info('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                return hexlify(decryptedKey).decode('latin-1')

    def run(self, profile):
        if profile.get('mkfiles'):
            return profile['mkfiles']
        founds = {}
        self.dpapiSystem = {}
        files = os.path.join(profile['APPDATA'], 'Microsoft', 'Protect', profile['SID'])
        if not os.path.isdir(files):
            return
        lsa_secs = LsaSecrets().run(profile)
        if lsa_secs:
            for k, v in lsa_secs['logon_sessions'].items():
                for found in v['dpapi_creds']:
                    if found['credtype'] == 'dpapi' and found.get('masterkey'):
                        founds[found['key_guid'].lower()] = found['masterkey']
                if v['msv_creds'] and v['sid'] == profile['SID']:
                    self.dpapiSystem['NTHASH'] = v['msv_creds'][0]['NThash']
                    self.dpapiSystem['SHAHASH'] = v['msv_creds'][0]['SHAHash']
        reg_secs = RegistrySecrets().run(profile)
        if reg_secs and reg_secs['SECURITY']['cached_secrets']:
            for i in reg_secs['SECURITY']['cached_secrets']:
                if i['key_name'] == 'DPAPI_SYSTEM' and i['history'] == False:
                    self.dpapiSystem.update({'MachineKey': i['machine_key'], 'UserKey': i['user_key']})
                elif i['key_name'] == 'NL$KM' and i['history'] == False:
                    self.dpapiSystem.update({'NL$KM': i['raw_secret']})

        for file in os.listdir(files):
            if file.lower() == "preferred" or file.lower() in founds:
                continue
            try:
                found = self.decrypt(os.path.join(files, file), profile)
                if found:
                    founds[file.lower()] = found
            except Exception:
                log.error(traceback.format_exc())
        return founds


modules = {"MasterKeyFiles": MasterKeyFiles()}
