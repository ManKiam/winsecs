# -*- coding: utf-8 -*-
from winsecs.utils import OpenKey, winreg


class WindowsPassword:
    def is_in_domain(self):
        """
        Return the context of the host
        If a domain controller is set we are in an active directory.
        """
        try:
            key = OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\')
            val, _ = winreg.QueryValueEx(key, 'DCName')
            winreg.CloseKey(key)
            return val
        except Exception:
            return False


    def get_cleartext_password(self, guid=None):
        """
        Get cleartext password if already found of the associated guid.
        If not guid specify, return the associated password of the preferred guid.
        """
        if not guid:
            guid = self.get_preferred_guid()

        if guid:
            return self.keys.get(guid, {}).get('password')

    def run(self, profile):
        """
        - Check if the user password has already be found using Pypykatz
        - If not, check if a password stored in another application is also used as windows password
        - Windows password not found, return the DPAPI hash (not admin priv needed) to bruteforce using John or Hashcat
        """
    pass
    #     file = os.path.join(profile['APPDATA'], 'Microsoft', 'Protect', profile['SID'], 'Preferred')
    #     mkfiles = profile.get('mkfiles')
    #     if not os.path.isfile(file) or not mkfiles:
    #         return

    #     # Check if a password already found is a windows password
    #     with open(file, 'rb') as pfile:
    #         GUID1 = struct.unpack("<LHH", pfile.read(8))
    #         GUID2 = struct.unpack(">HLH", pfile.read(8))

    #     preferred_guid = f"{GUID1[0]:08x}-{GUID1[1]:04x}-{GUID1[2]:04x}-{GUID2[0]:04x}-{GUID2[1]:08x}{GUID2[2]:04x}"
    #     masterkey = mkfiles.get(preferred_guidظ.lower())
    #     password = self.get_cleartext_password()
    #     if password:
    #         return {'Login': constant.username, 'Password': password}
    #     else:
    #         # Retrieve dpapi hash used to bruteforce (hash can be retrieved without needed admin privilege)
    #         # Method taken from Jean-Christophe Delaunay - @Fist0urs
    #         # https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf

    #         log.info('Windows passwords not found.\nTry to bruteforce this hash (using john or hashcat)')
    #         if constant.user_dpapi:
    #             context = 'local'
    #             if self.is_in_domain():
    #                 context = 'domain'

    #             h = constant.user_dpapi.get_dpapi_hash(context=context)
    #             if h:
    #                 pwd_found.append({
    #                     'Dpapi_hash_{context}'.format(context=context): constant.user_dpapi.get_dpapi_hash(
    #                                                                                             context=context)
    #                 })

    # return pwd_found


modules = {"WindowsPassword": WindowsPassword()}
