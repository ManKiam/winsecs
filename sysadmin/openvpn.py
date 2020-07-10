import win32crypt
from winsecs.utils import OpenKey, winreg, log


class OpenVPN:
    def check_openvpn_installed(self):
        try:
            key = OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\OpenVPN-GUI\\Configs')
            return key
        except Exception as e:
            log.debug(str(e))

    def run(self):
        key = self.check_openvpn_installed()
        if not key:
            return
        pwd_found = []
        num_profiles = winreg.QueryInfoKey(key)[0]
        for n in range(num_profiles):
            name_skey = winreg.EnumKey(key, n)
            skey = OpenKey(key, name_skey)
            values = {'Profile': name_skey}
            try:
                encrypted_password = winreg.QueryValueEx(skey, "auth-data")[0]
                entropy = winreg.QueryValueEx(skey, "entropy")[0][:-1]
                password = win32crypt.CryptUnprotectData(encrypted_password, None, entropy, None, 0)[1].decode()
                values['Password'] = password.decode('utf16')
            except Exception as e:
                log.debug(str(e))
            pwd_found.append(values)
            winreg.CloseKey(skey)
        winreg.CloseKey(key)

        return pwd_found


modules = {"OpenVPN": OpenVPN()}
