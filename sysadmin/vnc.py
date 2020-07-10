# Code based on vncpasswd.py by trinitronx
# https://github.com/trinitronx/vncpasswd.py
import binascii
import codecs
import os
import traceback

from struct import pack, unpack
from winsecs.utils import OpenKey, winreg, log


###################################################
#
# start: changes made for VNC.
#

# This constant was taken from vncviewer/rfb/vncauth.c:
vnckey = [23, 82, 107, 6, 35, 78, 88, 7]

# This is a departure from the original code.
# bytebit = [ 0200, 0100, 040, 020, 010, 04, 02, 01 ] # original
bytebit = [0o1, 0o2, 0o4, 0o10, 0o20, 0o40, 0o100, 0o200]  # VNC version


# two password functions for VNC protocol.


def decrypt_passwd(data):
    dk = deskey(pack('8B', *vnckey), True)
    return desfunc(data, dk)


def generate_response(passwd, challange):
    ek = deskey((passwd+'\x00'*8)[:8], False)
    return desfunc(challange[:8], ek) + desfunc(challange[8:], ek)

###
#  end: changes made for VNC.
#
###################################################


bigbyte = [
    0x800000,    0x400000,    0x200000,    0x100000,
    0x80000,    0x40000,    0x20000,    0x10000,
    0x8000,    0x4000,    0x2000,    0x1000,
    0x800,     0x400,     0x200,     0x100,
    0x80,    0x40,        0x20,        0x10,
    0x8,        0x4,        0x2,        0x1
]

# Use the key schedule specified in the Standard (ANSI X3.92-1981).

pc1 = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3
]

totrot = [1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28]

pc2 = [
    13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
]


def deskey(key, decrypt):  # Thanks to James Gillogly & Phil Karn!
    key = unpack('8B', key)

    pc1m = [0]*56
    pcr = [0]*56
    kn = [0]*32

    for j in range(56):
        l = pc1[j]
        m = l & 0o7
        if key[l >> 3] & bytebit[m]:
            pc1m[j] = 1
        else:
            pc1m[j] = 0

    for i in range(16):
        if decrypt:
            m = (15 - i) << 1
        else:
            m = i << 1
        n = m + 1
        kn[m] = kn[n] = 0
        for j in range(28):
            l = j + totrot[i]
            if l < 28:
                pcr[j] = pc1m[l]
            else:
                pcr[j] = pc1m[l - 28]
        for j in range(28, 56):
            l = j + totrot[i]
            if l < 56:
                pcr[j] = pc1m[l]
            else:
                pcr[j] = pc1m[l - 28]
        for j in range(24):
            if pcr[pc2[j]]:
                kn[m] |= bigbyte[j]
            if pcr[pc2[j+24]]:
                kn[n] |= bigbyte[j]

    return cookey(kn)


def cookey(raw):
    key = []
    for i in range(0, 32, 2):
        (raw0, raw1) = (raw[i], raw[i+1])
        k = (raw0 & 0x00fc0000) << 6
        k |= (raw0 & 0x00000fc0) << 10
        k |= (raw1 & 0x00fc0000) >> 10
        k |= (raw1 & 0x00000fc0) >> 6
        key.append(k)
        k = (raw0 & 0x0003f000) << 12
        k |= (raw0 & 0x0000003f) << 16
        k |= (raw1 & 0x0003f000) >> 4
        k |= (raw1 & 0x0000003f)
        key.append(k)
    return key


SP1 = [
    0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004
]

SP2 = [
    0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000
]

SP3 = [
    0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200
]

SP4 = [
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080
]

SP5 = [
    0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100
]

SP6 = [
    0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010
]

SP7 = [
    0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002
]

SP8 = [
    0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000
]


def desfunc(block, keys):
    (leftt, right) = unpack('>II', block)

    work = ((leftt >> 4) ^ right) & 0x0f0f0f0f
    right ^= work
    leftt ^= (work << 4)
    work = ((leftt >> 16) ^ right) & 0x0000ffff
    right ^= work
    leftt ^= (work << 16)
    work = ((right >> 2) ^ leftt) & 0x33333333
    leftt ^= work
    right ^= (work << 2)
    work = ((right >> 8) ^ leftt) & 0x00ff00ff
    leftt ^= work
    right ^= (work << 8)
    right = ((right << 1) | ((right >> 31) & 1)) & 0xffffffff
    work = (leftt ^ right) & 0xaaaaaaaa
    leftt ^= work
    right ^= work
    leftt = ((leftt << 1) | ((leftt >> 31) & 1)) & 0xffffffff

    for i in range(0, 32, 4):
        work = (right << 28) | (right >> 4)
        work ^= keys[i]
        fval = SP7[work & 0x3f]
        fval |= SP5[(work >> 8) & 0x3f]
        fval |= SP3[(work >> 16) & 0x3f]
        fval |= SP1[(work >> 24) & 0x3f]
        work = right ^ keys[i+1]
        fval |= SP8[work & 0x3f]
        fval |= SP6[(work >> 8) & 0x3f]
        fval |= SP4[(work >> 16) & 0x3f]
        fval |= SP2[(work >> 24) & 0x3f]
        leftt ^= fval
        work = (leftt << 28) | (leftt >> 4)
        work ^= keys[i+2]
        fval = SP7[work & 0x3f]
        fval |= SP5[(work >> 8) & 0x3f]
        fval |= SP3[(work >> 16) & 0x3f]
        fval |= SP1[(work >> 24) & 0x3f]
        work = leftt ^ keys[i+3]
        fval |= SP8[work & 0x3f]
        fval |= SP6[(work >> 8) & 0x3f]
        fval |= SP4[(work >> 16) & 0x3f]
        fval |= SP2[(work >> 24) & 0x3f]
        right ^= fval

    right = (right << 31) | (right >> 1)
    work = (leftt ^ right) & 0xaaaaaaaa
    leftt ^= work
    right ^= work
    leftt = (leftt << 31) | (leftt >> 1)
    work = ((leftt >> 8) ^ right) & 0x00ff00ff
    right ^= work
    leftt ^= (work << 8)
    work = ((leftt >> 2) ^ right) & 0x33333333
    right ^= work
    leftt ^= (work << 2)
    work = ((right >> 16) ^ leftt) & 0x0000ffff
    leftt ^= work
    right ^= (work << 16)
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0f
    leftt ^= work
    right ^= (work << 4)

    leftt &= 0xffffffff
    right &= 0xffffffff
    return pack('>II', right, leftt)


class Vnc:
    def split_len(self, seq, length):
        return [seq[i:i + length] for i in range(0, len(seq), length)]

    def do_crypt(self, password, decrypt):
        passpadd = (password + '\x00' * 8)[:8]
        strkey = b''.join([bytes([x]) for x in vnckey])
        key = deskey(strkey, decrypt)
        crypted = desfunc(passpadd, key)
        return crypted

    def unhex(self, s):
        try:
            s = codecs.decode(s, 'hex')
        except TypeError as e:
            if e.message == 'Odd-length string':
                log.debug('%s . Chopping last char off... "%s"' % (e.message, s[:-1]))
                s = codecs.decode(s[:-1], 'hex')
            else:
                return False
        return s

    def reverse_vncpassword(self, hash):
        encpasswd = self.unhex(hash)
        pwd = None
        if encpasswd:
            # If the hex encoded passwd length is longer than 16 hex chars and divisible
            # by 16, then we chop the passwd into blocks of 64 bits (16 hex chars)
            # (1 hex char = 4 binary bits = 1 nibble)
            hexpasswd = codecs.encode(encpasswd, 'hex')
            if len(hexpasswd) > 16 and (len(hexpasswd) % 16) == 0:
                splitstr = self.split_len(codecs.encode(hash, 'hex'), 16)
                cryptedblocks = []
                for sblock in splitstr:
                    cryptedblocks.append(self.do_crypt(codecs.decode(sblock, 'hex'), True))
                    pwd = b''.join(cryptedblocks)
            elif len(hexpasswd) <= 16:
                pwd = self.do_crypt(encpasswd, True)
            else:
                pwd = self.do_crypt(encpasswd, True)
        return pwd

    def vnc_from_registry(self):
        pfound = []
        vncs = (
            ('RealVNC 4.x', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 3.x', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\vncserver', 'Password'),
            ('RealVNC 4.x', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 4.x', 'HKEY_CURRENT_USER\\SOFTWARE\\RealVNC\\WinVNC4', 'Password'),
            ('RealVNC 3.x', 'HKEY_CURRENT_USER\\Software\\ORL\\WinVNC3', 'Password'),
            ('TightVNC', 'HKEY_CURRENT_USER\\Software\\TightVNC\\Server', 'Password'),
            ('TightVNC', 'HKEY_CURRENT_USER\\Software\\TightVNC\\Server', 'PasswordViewOnly'),
            ('TightVNC', 'HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server', 'Password'),
            ('TightVNC ControlPassword', 'HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server', 'ControlPassword'),
            ('TightVNC', 'HKEY_LOCAL_MACHINE\\Software\\TightVNC\\Server', 'PasswordViewOnly'),
            ('TigerVNC', 'HKEY_LOCAL_MACHINE\\Software\\TigerVNC\\Server', 'Password'),
            ('TigerVNC', 'HKEY_CURRENT_USER\\Software\\TigerVNC\\Server', 'Password'),
        )

        for vnc in vncs:
            try:
                if vnc[1].startswith('HKEY_LOCAL_MACHINE'):
                    hkey = OpenKey(winreg.HKEY_LOCAL_MACHINE, vnc[1].replace('HKEY_LOCAL_MACHINE\\', ''))

                elif vnc[1].startswith('HKEY_CURRENT_USER'):
                    hkey = OpenKey(winreg.HKEY_CURRENT_USER, vnc[1].replace('HKEY_CURRENT_USER\\', ''))

                reg_key = winreg.QueryValueEx(hkey, vnc[2])[0]
            except Exception:
                log.debug('Problems with key:: {reg_key}'.format(reg_key=vnc[1]))
                continue

            try:
                enc_pwd = binascii.hexlify(reg_key).decode()
            except Exception:
                log.debug('Problems with decoding: {reg_key}'.format(reg_key=reg_key))
                continue

            values = {}
            try:
                password = self.reverse_vncpassword(enc_pwd)
                if password:
                    values['Password'] = password
            except Exception:
                log.info('Problems with reverse_vncpassword: {reg_key}'.format(reg_key=reg_key))
                continue

            values['Server'] = vnc[0]
            # values['Hash'] = enc_pwd
            pfound.append(values)

        return pfound

    def vnc_from_filesystem(self):
        # os.environ could be used here because paths are identical between users
        pfound = []
        vncs = (
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd2'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\uvnc bvba\\UltraVNC\\ultravnc.ini', 'passwd2'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['PROGRAMFILES'] + '\\UltraVNC\\ultravnc.ini', 'passwd2'),
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\UltraVNC\\ultravnc.ini', 'passwd'),
            ('UltraVNC', os.environ['ProgramFiles(x86)'] + '\\UltraVNC\\ultravnc.ini', 'passwd2'),
        )

        for vnc in vncs:
            string_to_match = vnc[2] + '='
            enc_pwd = ''
            try:
                with open(vnc[1], 'r') as file:
                    for line in file:
                        if string_to_match in line:
                            enc_pwd = line.replace(string_to_match, '').replace('\n', '')
            except Exception:
                log.debug('Problems with file: {file}'.format(file=vnc[1]))
                continue

            values = {}
            try:
                password = self.reverse_vncpassword(enc_pwd)
                if password:
                    values['Password'] = password
            except Exception:
                log.debug('Problems with reverse_vncpassword: {enc_pwd}'.format(enc_pwd=enc_pwd))
                log.debug(traceback.format_exc())
                continue

            values['Server'] = vnc[0]
            # values['Hash'] = enc_pwd
            pfound.append(values)

        return pfound

    def vnc_from_process(self):
        # Not yet implemented
        return []

    def run(self):
        return self.vnc_from_filesystem() + self.vnc_from_registry() + self.vnc_from_process()


modules = {"Vnc": Vnc()}
