# -*- coding: utf-8 -*-
import os


class Wsl:
    def run(self, profile):
        pwd_found = []
        shadow_files_list = []

        # Old WSL PATH
        old_path = os.path.join(profile['LOCALAPPDATA'], 'lxss\\rootfs\\etc\\shadow')

        if os.path.exists(old_path):
            shadow_files_list.append(old_path)

        # New WSL PATH need to look into Package folder
        new_path = os.path.join(profile['LOCALAPPDATA'], 'Packages\\')
        if os.path.exists(new_path):
            for root, dirs, files in os.walk(new_path):
                for file in files:
                    if file == "shadow":
                        shadow_files_list.append(os.path.join(root, file))

        # Extract the hashes
        for shadow in shadow_files_list:
            with open(shadow, 'r') as shadow_file:
                for line in shadow_file.readlines():
                    user_hash = line.replace('\n', '')
                    line = user_hash.split(':')

                    # Check if a password is defined
                    if not line[1] in ['x', '*', '!']:
                        pwd_found.append({
                            'Hash': ':'.join(user_hash.split(':')[1:]),
                            'Login': user_hash.split(':')[0].replace('\n', '')
                        })
        return pwd_found


modules = {"Wsl": Wsl()}
