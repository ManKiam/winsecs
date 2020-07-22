# -*- coding: utf-8 -*-
import os
import traceback
from datetime import datetime
from impacket.dpapi import CredentialFile, DPAPI_BLOB, CREDENTIAL_BLOB
from .mkfiles import MasterKeyFiles
from winsecs.utils import bin_to_string, log, getUnixTime
from binascii import unhexlify


class CredFiles:
    def run(self, profile):
        pwd_found = []

        mkfiles = MasterKeyFiles().run(profile)
        creds_directory = os.path.join(profile['LOCALAPPDATA'], 'Microsoft', 'Credentials')
        creds_directory2 = os.path.join(profile['APPDATA'], 'Microsoft', 'Credentials')
        if (not os.path.isdir(creds_directory) and not os.path.isdir(creds_directory2)) or not mkfiles:
            return
        for folder in [creds_directory, creds_directory2]:
            for cred_file in os.listdir(folder):
                try:
                    data = open(os.path.join(folder, cred_file), 'rb').read()
                    cred = CredentialFile(data)
                    blob = DPAPI_BLOB(cred['Data'])

                    masterkey = mkfiles.get(bin_to_string(blob['GuidMasterKey']).lower())

                    if masterkey:
                        key = unhexlify(masterkey)
                        decrypted = blob.decrypt(key)
                        blob = CREDENTIAL_BLOB(decrypted)
                        if decrypted is not None:
                            pwd_found.append({
                                'Target': blob['Target'].decode('utf-16-le'),
                                'Username': blob['Username'].decode('utf-16-le'),
                                'Password': blob['Unknown3'].decode('utf-16-le'),
                                'LastWritten': datetime.utcfromtimestamp(getUnixTime(blob['LastWritten']))
                            })
                except Exception:
                    log.error(traceback.format_exc())

            return pwd_found


modules = {"CredFiles": CredFiles()}