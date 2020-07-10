# -*- coding: utf-8 -*-
from .mkfiles import MasterKeyFiles
from impacket.dpapi import VAULT_VCRD, VAULT_VPOL, VAULT_KNOWN_SCHEMAS, VAULT_VPOL_KEYS
from winsecs.utils import bin_to_string
from binascii import unhexlify
from Crypto.Cipher import AES
import os


class VaultFiles:
    def run(self, profile):
        pass
        # pwd_found = {}

        # mkfiles = MasterKeyFiles().run(profile)
        # main_vault_directory = os.path.join(profile['LOCALAPPDATA'], 'Microsoft', 'Vault')
        # if not os.path.isdir(main_vault_directory) or not mkfiles:
        #     return

        # for i in os.listdir(main_vault_directory):
        #     vault_dir = os.path.join(main_vault_directory)
        #     vault_policy = os.path.join(vault_dir, 'Policy.vpol')
        #     if not os.path.isdir(vault_dir) or not os.path.isfile(vault_policy):
        #         continue
        #     data = open(vault_policy, 'rb').read()
        #     vpol = VAULT_VPOL(data)
        #     data = ''
        #     blob = vpol['Blob']
        #     for key in mkfiles.values():
        #         key = unhexlify(key)
        #         try:
        #             data = blob.decrypt(key)
        #             break
        #         except:
        #             pass
        #     if not data:
        #         continue
        #     vpol_keys = VAULT_VPOL_KEYS(data)
        #     key_aes128 = vpol_keys['Key1']['bKeyBlob']['bKey']
        #     key_aes256 = vpol_keys['Key2']['bKeyBlob']['bKey']

        #     for f in os.listdir(vault_dir):
        #         if f.lower() == 'policy.vpol':
        #             continue
        #         if f.lower().endswith('.vcrd'):
        #             data = open(os.path.join(root, f), 'rb').read()
        #             blob = VAULT_VCRD(data)

        #                 key = unhexlify(masterkey)
        #                 cleartext = None
        #                 for i, entry in enumerate(blob.attributesLen):
        #                     if entry > 28:
        #                         attribute = blob.attributes[i]
        #                         if 'IV' in attribute.fields and len(attribute['IV']) == 16:
        #                             cipher = AES.new(key, AES.MODE_CBC, iv=attribute['IV'])
        #                         else:
        #                             cipher = AES.new(key, AES.MODE_CBC)
        #                         cleartext = cipher.decrypt(attribute['Data'])

        #                 if cleartext is not None:
        #                     # Lookup schema Friendly Name and print if we find one
        #                     if blob['FriendlyName'].decode('utf-16le')[:-1] in VAULT_KNOWN_SCHEMAS:
        #                         # Found one. Cast it and print
        #                         pwd_found[os.path.join(root, f)] = VAULT_KNOWN_SCHEMAS[blob['FriendlyName'].decode('utf-16le')[:-1]](cleartext).__dict__

        #         if f.lower().endswith('.vpol'):
        #             data = open(os.path.join(root, f), 'rb').read()
        #             vpol = VAULT_VPOL(data)

        #             masterkey = mkfiles.get(bin_to_string(vpol['GuidMasterKey']).lower())

        #             if masterkey:
        #                 key = unhexlify(masterkey)
        #                 blob = vpol['Blob']
        #                 data = blob.decrypt(key)
        #                 if data is not None:
        #                     pwd_found[os.path.join(root, f)] = VAULT_VPOL_KEYS(data).__dict__

        # return pwd_found


modules = {"VaultFiles": VaultFiles()}
