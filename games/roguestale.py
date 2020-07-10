# -*- coding: utf-8 -*-
import os
import re
from xml.etree.cElementTree import ElementTree
from winsecs.utils import log


class RoguesTale:
    def run(self, profile):
        creds = []
        directory = profile['USERPROFILE'] + '\\Documents\\Rogue\'s Tale\\users'

        # The actual user details are stored in *.userdata files
        if not os.path.exists(directory):
            return

        files = os.listdir(directory)

        for f in files:
            if re.match('.*\.userdata', f):
                # We've found a user file, now extract the hash and username

                xmlfile = directory + '\\' + f
                tree = ElementTree(file=xmlfile)
                root = tree.getroot()

                # Double check to make sure that the file is valid
                if root.tag != 'user':
                    log.warning('Profile %s does not appear to be valid' % f)
                    continue

                # Now save it to credentials
                creds.append({'Login': root.attrib['username'], 'Hash': root.attrib['password']})

        return creds


modules = {"RoguesTale": RoguesTale()}
