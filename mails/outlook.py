# -*- coding: utf-8 -*-
import win32crypt
from winsecs.utils import OpenKey, winreg, log


class Outlook:
    def trySingleKey(self, keyPath):
        try:
            hkey = OpenKey(winreg.HKEY_CURRENT_USER, keyPath)
        except Exception as e:
            log.debug(e)
            return

        num = winreg.QueryInfoKey(hkey)[0]
        pwd_found = []
        for x in range(0, num):
            name = winreg.EnumKey(hkey, x)
            skey = OpenKey(hkey, name, 0, winreg.ACCESS_READ)

            num_skey = winreg.QueryInfoKey(skey)[0]
            if num_skey != 0:
                for y in range(0, num_skey):
                    name_skey = winreg.EnumKey(skey, y)
                    sskey = OpenKey(skey, name_skey)
                    num_sskey = winreg.QueryInfoKey(sskey)[1]

                    for z in range(0, num_sskey):
                        k = winreg.EnumValue(sskey, z)
                        if 'password' in k[0].lower():
                            values = self.retrieve_info(sskey, name_skey)

                            if values:
                                pwd_found.append(values)

            winreg.CloseKey(skey)
        winreg.CloseKey(hkey)
        return pwd_found

    def retrieve_info(self, hkey, name_key):
        values = {}
        num = winreg.QueryInfoKey(hkey)[1]
        for x in range(0, num):
            k = winreg.EnumValue(hkey, x)
            if 'password' in k[0].lower():
                try:
                    password_bytes = win32crypt.CryptUnprotectData(k[1][1:], None, None, None, 0)[1]
                    #  password_bytes is <password in utf-16> + b'\x00\x00'
                    terminator = b'\x00\x00'
                    if password_bytes.endswith(terminator):
                        password_bytes = password_bytes[: -len(terminator)]

                    values[k[0]] = password_bytes.decode("utf-16")
                except Exception as e:
                    log.debug(str(e))
                    values[k[0]] = 'N/A'
            else:
                try:
                    values[k[0]] = k[1].decode('utf-16')
                except Exception:
                    values[k[0]] = str(k[1])
        return values

    def run(self):
        # https://github.com/0Fdemir/OutlookPasswordRecovery/blob/master/OutlookPasswordRecovery/Module1.vb
        key_paths = {
            "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook",
            "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles",
        }
        # https://docs.microsoft.com/en-us/previous-versions/office/jj228679(v=office.15)
        major_versions = {
            "7.0",  # Office 97
            "8.0",  # Office 98
            "9.0",  # Office 2000
            "10.0",  # Office XP
            "11.0",  # Office 2003
            "12.0",  # Office 2007
            "14.0",  # Office 2010
            "15.0",  # Office 2013
            "16.0",  # Office 2016
            "16.0",  # Office 2019
        }
        key_paths |= {"Software\\Microsoft\\Office\\%s\\Outlook\\Profiles\\Outlook" % x for x in major_versions}
        for key_path in key_paths:
            result = self.trySingleKey(keyPath=key_path)
            if result is not None:
                return result


modules = {"Outlook": Outlook()}
