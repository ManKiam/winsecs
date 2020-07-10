# -*- coding: utf-8 -*-
from binascii import unhexlify
from impacket.examples.secretsdump import LocalOperations, LSASecrets


class LsaSecrets:
    def getDPAPI_SYSTEM(self, secretType, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            machineKey = machineKey.split(':')[1][2:]
            userKey = userKey.split(':')[1][2:]
            self.dpapiSystem.update({'MachineKey': unhexlify(machineKey), 'UserKey': unhexlify(userKey)})
        elif secret.startswith("NL$KM:"):
            nlkm = secret.split(':')[1]
            self.dpapiSystem.update({'NL$KM': unhexlify(nlkm)})
        elif secret.startswith("L$_"):
            l_ = secret.split(':')[1]
            self.dpapiSystem.update({'user_recovery': unhexlify(l_).decode('utf-16-le')})

    def run(self, profile):
        self.dpapiSystem = {}
        if profile["security"] and profile["system"]:
            LSASecrets(
                profile["security"], LocalOperations(profile["system"]).getBootKey(),
                None, isRemote=False, history=False, perSecretCallback=self.getDPAPI_SYSTEM
            ).dumpSecrets()
        return self.dpapiSystem


modules = {"LsaSecrets": LsaSecrets()}
