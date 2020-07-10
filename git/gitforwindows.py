# -*- coding: utf-8 -*-
import os

from urllib.parse import urlparse, unquote


class GitForWindows:
    def run(self, profile):
        """
        Extract the credentials from a Git store file.
        See "https://git-scm.com/docs/git-credential-store" for file format.

        :param location: Full path to the Git store file
        :return: List of credentials founds
        """

        # According to the "git-credential-store" documentation:
        # Build a list of locations in which git credentials can be stored
        locations = [
            os.path.join(profile["USERPROFILE"], '.git-credentials'),
            os.path.join(profile["USERPROFILE"], '.config\\git\\credentials'),
        ]
        if "XDG_CONFIG_HOME" in os.environ:
            locations.append(os.path.join(os.environ.get('XDG_CONFIG_HOME'), 'git\\credentials'))

        # Apply the password extraction on the defined locations
        pwd_found = set()
        for location in locations:
            if not os.path.isfile(location):
                continue
            with open(location) as f:
                # One line have the following format: https://user:pass@example.com
                for cred in f:
                    if cred:
                        parts = urlparse(cred)
                        pwd_found.add([
                            unquote(parts.geturl().replace(parts.username + ":" + parts.password + "@", "").strip()),
                            unquote(parts.username),
                            unquote(parts.password)
                        ])

        # Filter duplicates
        return list(pwd_found)


modules = {"GitForWindows": GitForWindows()}
