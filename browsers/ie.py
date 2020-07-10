import hashlib
import subprocess
import traceback
import win32crypt

from winsecs.utils import OpenKey, platform, winreg, log


class IE:
    def get_hash_table(self):
        # get the url list
        urls = self.get_history()

        # calculate the hash for all urls found on the history
        hash_tables = []
        for u in range(len(urls)):
            try:
                h = (urls[u] + '\0').encode('UTF-16LE')
                hash_tables.append([h, hashlib.sha1(h).hexdigest().lower()])
            except Exception:
                log.debug(traceback.format_exc())
        return hash_tables

    def get_history(self):
        urls = self.history_from_regedit()
        try:
            urls = urls + self.history_from_powershell()
        except Exception:
            log.debug(traceback.format_exc())

        urls = urls + [
            'https://www.facebook.com/', 'https://www.gmail.com/',
            'https://accounts.google.com/', 'https://accounts.google.com/servicelogin'
        ]
        return urls

    def history_from_powershell(self):
        # From https://richardspowershellblog.wordpress.com/2011/06/29/ie-history-to-csv/
        cmdline = '''
        function get-iehistory {
        [CmdletBinding()]
        param ()

        $shell = New-Object -ComObject Shell.Application
        $hist = $shell.NameSpace(34)
        $folder = $hist.Self

        $hist.Items() |
        foreach {
            if ($_.IsFolder) {
            $siteFolder = $_.GetFolder
            $siteFolder.Items() |
            foreach {
                $site = $_

                if ($site.IsFolder) {
                $pageFolder  = $site.GetFolder
                $pageFolder.Items() |
                foreach {
                    $visit = New-Object -TypeName PSObject -Property @{
                        URL = $($pageFolder.GetDetailsOf($_,0))
                    }
                    $visit
                }
                }
            }
            }
        }
        }
        get-iehistory
        '''
        command = ['powershell.exe', '/c', cmdline]
        p = subprocess.Popen(
            command, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE,
            stdin=subprocess.PIPE, universal_newlines=True
        )
        results, _ = p.communicate()

        urls = []
        for r in results.split('\n'):
            if r.startswith('http'):
                urls.append(r.strip())
        return urls

    def history_from_regedit(self):
        urls = []
        try:
            hkey = OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Internet Explorer\\TypedURLs')
        except Exception:
            log.debug(traceback.format_exc())
            return []

        num = winreg.QueryInfoKey(hkey)[1]
        for x in range(0, num):
            k = winreg.EnumValue(hkey, x)
            if k:
                urls.append(k[1])
        winreg.CloseKey(hkey)
        return urls

    def decipher_password(self, cipher_text, u):
        pwd_found = set()
        # deciper the password
        pwd = win32crypt.CryptUnprotectData(cipher_text, None, u, None, 0)[1]
        if not pwd:
            return []

        separator = b"\x00\x00"
        if pwd.endswith(separator):
            pwd = pwd[: -len(separator)]

        # <pwd_n>, <login_n>, ..., <pwd_0>, <login_0>, <SOME_SERVICE_DATA_CHUNKS>
        chunks_reversed = pwd.rsplit(separator)[::-1]

        #  Filter out service data
        possible_passwords = [x for n, x in enumerate(chunks_reversed) if n % 2 == 0]
        possible_logins = [x for n, x in enumerate(chunks_reversed) if n % 2 == 1]
        for possible_login, possible_password in zip(possible_logins, possible_passwords):
            #  Service data starts with several blocks of "<2_bytes>\x00\x00<10_bytes>"
            if len(pwd_found) > 0 and len(possible_login) == 2 and len(possible_password) == 10:
                break

            try:
                possible_login_str = possible_login.decode('UTF-16LE')
                possible_password_str = possible_password.decode('UTF-16LE')
            except UnicodeDecodeError:
                if pwd_found:
                    #  Some passwords have been found. Assume this is service data.
                    break

                #  No passwords have been found. Assume login or password contains some chars which could not be decoded
                possible_login_str = str(possible_password)
                possible_password_str = str(possible_password)

            pwd_found.add([u.decode('UTF-16LE'), possible_login_str, possible_password_str])

        return pwd_found

    def run(self):
        if float('.'.join(platform.version().split('.')[:2])) > 6.1:
            log.debug('Internet Explorer passwords are stored in Vault (check vault module)')
            return

        pwd_found = set()
        try:
            hkey = OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2')
        except Exception:
            log.debug(traceback.format_exc())
        else:
            nb_site = 0
            nb_pass_found = 0

            # retrieve the urls from the history
            hash_tables = self.get_hash_table()

            num = winreg.QueryInfoKey(hkey)[1]
            for x in range(0, num):
                k = winreg.EnumValue(hkey, x)
                if k:
                    nb_site += 1
                    for h in hash_tables:
                        # both hash are similar, we can decipher the password
                        if h[1] == k[0][:40].lower():
                            nb_pass_found += 1
                            cipher_text = k[1]
                            pwd_found |= self.decipher_password(cipher_text, h[0])
                            break

            winreg.CloseKey(hkey)

            # manage errors
            if nb_site > nb_pass_found:
                log.error('%s hashes have not been decrypted, the associate website used to decrypt the '
                           'passwords has not been found' % str(nb_site - nb_pass_found))

        return list(pwd_found)


modules = {"IE": IE()}
