# -*- coding: utf-8 -*-

# Password are stored in cleartext on old system (< 2008 R2 and < Win7)
# If enabled on recent system, the password should be visible on the lsa secrets dump (check lsa module output)
from winsecs.utils import OpenKey, winreg, log


class Autologon:
    def run(self):
        pwd_found = []
        try:
            hkey = OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            if int(winreg.QueryValueEx(hkey, 'AutoAdminLogon')[0]) == 1:
                log.debug('Autologin enabled')

                keys = {
                    'DefaultDomainName': '',
                    'DefaultUserName': '',
                    'DefaultPassword': '',
                    'AltDefaultDomainName': '',
                    'AltDefaultUserName': '',
                    'AltDefaultPassword': '',
                }

                to_remove = []
                for k in keys:
                    try:
                        keys[k] = str(winreg.QueryValueEx(hkey, k)[0])
                    except Exception:
                        to_remove.append(k)

                for r in to_remove:
                    keys.pop(r)

                if keys:
                    pwd_found.append(keys)

        except Exception as e:
            log.debug(str(e))

        return pwd_found


modules = {"Autologon": Autologon()}
