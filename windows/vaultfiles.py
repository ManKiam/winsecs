# -*- coding: utf-8 -*-
from impacket.dpapi import VAULT_VCRD, VAULT_VPOL, VAULT_KNOWN_SCHEMAS, VAULT_VPOL_KEYS
# from winsecs.utils import bin_to_string
from binascii import unhexlify
from Crypto.Cipher import AES
import os


class VaultFiles:
    def run(self, profile):
        pwd_found = {}

        mkfiles = profile.get('mkfiles')
        main_vault_directory = os.path.join(profile['LOCALAPPDATA'], 'Microsoft', 'Vault')
        if not os.path.isdir(main_vault_directory) or not mkfiles:
            return

        for i in os.listdir(main_vault_directory):
            vault_dir = os.path.join(main_vault_directory, i)
            vault_policy = os.path.join(vault_dir, 'Policy.vpol')
            if not os.path.isdir(vault_dir) or not os.path.isfile(vault_policy):
                continue
            data = open(vault_policy, 'rb').read()
            vpol = VAULT_VPOL(data)
            data = ''
            blob = vpol['Blob']
            for key in mkfiles.values():
                key = unhexlify(key)
                try:
                    data = blob.decrypt(key)
                    break
                except:
                    pass
            if not data:
                continue
            vpol_keys = VAULT_VPOL_KEYS(data)
            key_aes128 = vpol_keys['Key1']['bKeyBlob']['bKey']
            key_aes256 = vpol_keys['Key2']['bKeyBlob']['bKey']

            for f in os.listdir(vault_dir):
                if f.lower() == 'policy.vpol':
                    continue
                if f.lower().endswith('.vcrd'):
                    blob = VAULT_VCRD(open(os.path.join(vault_dir, f), 'rb').read())
                    name = blob['FriendlyName'].decode('utf-16le').rstrip('\0')
                    if name not in VAULT_KNOWN_SCHEMAS:
                        name = 'Internet Explorer'

                    for i, attribute in enumerate(blob.attributes):
                        if len(attribute.fields.get('IV', '')) == 16:
                            cipher = AES.new(key_aes256, AES.MODE_CBC, iv=attribute['IV'])
                            cleartext = cipher.decrypt(attribute['Data'])

                            decrypted = VAULT_KNOWN_SCHEMAS[name](cleartext)
                            pwd = decrypted['Password']
                            try:
                                pwd = pwd.decode('utf-16-le').rstrip('\0')
                            except:
                                pass
                            pwd_found[os.path.join(vault_dir, f)] = {
                                'URL': decrypted['Resource'].decode('utf-16-le').rstrip('\0'),
                                'Login': decrypted['Username'].decode('utf-16-le').rstrip('\0'),
                                'Password': pwd
                            }

        return pwd_found


modules = {"VaultFiles": VaultFiles()}
