# -*- coding: utf-8 -*-
import win32cred


class Credman:
    def run(self):
        pwd_found = []
        # FOR XP
        # - password are encrypted with specific salt depending on its Type
        # entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\\0' # FOR CRED_TYPE_GENERIC
        # entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\\0' # FOR CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
        # CryptUnprotectData(byref(blobIn),None,byref(blobEntropy),None,None,CRYPTPROTECT_UI_FORBIDDEN,byref(blobOut))

        # # creds = POINTER(PCREDENTIAL)()
        # # count = c_ulong()

        # # if CredEnumerate(None, 0, byref(count), byref(creds)) == 1:
        # #     for i in range(count.value):
        # #         c = creds[i].contents
        # #         if c.Type == CRED_TYPE_GENERIC or c.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
        # #             # Remove password too long
        # #             if c.CredentialBlobSize.real < 200:
        # #                 pwd_found.append({
        # #                     'URL': c.TargetName,
        # #                     'Login': c.UserName,
        # #                     'Password': c.CredentialBlob[:c.CredentialBlobSize.real].replace(b"\x00", b"")
        # #                 })

        # #     CredFree(creds)
        for i in win32cred.CredEnumerate(None, 0):
            if i["Type"] in [win32cred.CRED_TYPE_GENERIC, win32cred.CRED_TYPE_DOMAIN_CERTIFICATE, win32cred.CRED_TYPE_DOMAIN_VISIBLE_PASSWORD]:
                pwd = i['CredentialBlob']
                if pwd.endswith(b"\x00\x00\x00"):
                    pwd = pwd.replace(b'\x00', b'')
                pwd_found.append({
                    'URL': i['TargetName'],
                    'Login': i['UserName'],
                    'Password': pwd,
                    'LastWritten': str(i['LastWritten'])
                })

        return pwd_found


modules = {"Credman": Credman()}
