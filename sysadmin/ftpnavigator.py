# -*- coding: utf-8 -*-
import struct
import os


class FtpNavigator:
    def decode(self, encode_password):
        password = ''
        for p in encode_password:
            password += chr(struct.unpack('B', p)[0] ^ 0x19)
        return password

    def run(self, profile):
        path = os.path.join(profile['HOMEDRIVE'], 'FTP Navigator', 'Ftplist.txt')
        elements = {'Name': 'Name', 'Server': 'Host', 'Port': 'Port', 'User': 'Login', 'Password': 'Password'}
        if not os.path.exists(path):
            return

        pwd_found = []
        with open(path, 'r') as f:
            for ff in f:
                values = {}
                info = ff.split(';')
                for i in info:
                    i = i.split('=')
                    for e in elements:
                        if i[0] == e:
                            if i[0] == "Password" and i[1] != '1' and i[1] != '0':
                                values['Password'] = self.decode(i[1])
                            else:
                                values[elements[i[0]]] = i[1]

                # used to save the password if it is an anonymous authentication
                if values['Login'] == 'anonymous' and 'Password' not in values:
                    values['Password'] = 'anonymous'

                pwd_found.append(values)

        return pwd_found


modules = {"FtpNavigator": FtpNavigator()}
