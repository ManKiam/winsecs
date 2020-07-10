# -*- coding: utf-8 -*-
import os
from xml.etree.cElementTree import ElementTree
from glob import glob
from itertools import cycle

from winsecs.utils import char_to_int


class PSI:

    # Thanks to https://github.com/jose1711/psi-im-decrypt
    def decode_password(self, password, jid):
        result = ''
        jid = cycle(jid)
        for n1 in range(0, len(password), 4):
            x = int(password[n1:n1 + 4], 16)
            result += chr(x ^ char_to_int(next(jid)))

        return result

    def run(self, profile):
        pwd_found = set()

        for one_dir in ('psi\\profiles\\*\\accounts.xml', 'psi+\\profiles\\*\\accounts.xml'):
            _path = os.path.join(profile['APPDATA'] , one_dir)
            accs_files = glob(_path)
            for one_file in accs_files:
                self.process_one_file(one_file)
                root = ElementTree(file=one_file).getroot()

                for item in root:
                    if item.tag == '{http://psi-im.org/options}accounts':
                        for acc in item:
                            values = {}

                            for x in acc:
                                if x.tag == '{http://psi-im.org/options}jid':
                                    values['Login'] = x.text

                                elif x.tag == '{http://psi-im.org/options}password':
                                    values['Password'] = x.text

                            values['Password'] = self.decode_password(values['Password'], values['Login'])

                            if values:
                                pwd_found.add(list(values.values()))

        return list(pwd_found)


modules = {"PSI": PSI()}
