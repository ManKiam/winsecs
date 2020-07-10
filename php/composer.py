# -*- coding: utf-8 -*-
import json
import os


class Composer:
    def run(self, profile):
        """
        Extract the credentials from the "auth.json" file.
        See "https://getcomposer.org/doc/articles/http-basic-authentication.md" for file format.
        :param location: Full path to the "auth.json" file
        :return: List of credentials founds
        """

        # Define the possible full path of the "auth.json" file when is defined at global level
        # See "https://getcomposer.org/doc/articles/http-basic-authentication.md"
        # See "https://seld.be/notes/authentication-management-in-composer"
        location = ''
        for tmp in [os.path.join(profile["COMPOSER_HOME"], 'auth.json'), os.path.join(profile["APPDATA"], 'Composer\\auth.json')]:
            if os.path.isfile(tmp):
                location = tmp
                break
        if not location:
            return

        pwd_found = []
        with open(location) as f:
            creds = json.load(f)
            for cred_type in creds:
                for domain in creds[cred_type]:
                    values = {"AuthenticationType" : cred_type, "Domain" : domain}
                    # Extract basic authentication if we are on a "http-basic" section
                    # otherwise extract authentication token
                    if cred_type == "http-basic":
                        values["Login"] = creds[cred_type][domain]["username"]
                        values["Password"] = creds[cred_type][domain]["password"]
                    else:
                        values["Password"] = creds[cred_type][domain]
                    pwd_found.append(values)

        return pwd_found


modules = {"Composer": Composer()}
