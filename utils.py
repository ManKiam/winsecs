import logging
import re
import base64
import subprocess
import psutil
from struct import unpack
import winreg
import platform

log = logging.getLogger('winsecs')


def OpenKey(key, path, index=0, access=winreg.KEY_READ):
    if "64" in platform.machine():
        return winreg.OpenKey(key, path, index, access | winreg.KEY_WOW64_64KEY)
    else:
        return winreg.OpenKey(key, path, index, access)


def char_to_int(string):
    if isinstance(string, str):
        string = ord(string)
    return string


def get_full_path_from_pid(pid):
    try:
        return psutil.Process(pid).exe()
    except:
        return ''


def getUnixTime(t):
    t -= 116444736000000000
    t //= 10000000
    return t


def bin_to_string(uuid):
    uuid1, uuid2, uuid3 = unpack('<LHH', uuid[:8])
    uuid4, uuid5, uuid6 = unpack('>HHL', uuid[8:16])
    return '%08X-%04X-%04X-%04X-%04X%08X' % (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)


def powershell_execute(script, func):
    """
    Execute a powershell script
    """
    output = ""
    try:
        script = re.sub("Write-Verbose ", "Write-Output ", script, flags=re.I)
        script = re.sub("Write-Error ", "Write-Output ", script, flags=re.I)
        script = re.sub("Write-Warning ", "Write-Output ", script, flags=re.I)

        full_args = ["powershell.exe", "-NoProfile", "-NoLogo", "-C", "-"]

        info = subprocess.STARTUPINFO()
        info.dwFlags = subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = subprocess.SW_HIDE

        p = subprocess.Popen(full_args, startupinfo=info, stdin=subprocess.PIPE, stderr=subprocess.STDOUT,
                             stdout=subprocess.PIPE, universal_newlines=True, shell=True)
        p.stdin.write("$base64=\"\"" + "\n")

        n = 25000
        b64_script = base64.b64encode(script)
        tab = [b64_script[i:i + n] for i in range(0, len(b64_script), n)]
        for t in tab:
            p.stdin.write("$base64+=\"%s\"\n" % t)
            p.stdin.flush()

        p.stdin.write("$d=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64))\n")
        p.stdin.write("Invoke-Expression $d\n")

        p.stdin.write("\n$a=Invoke-Expression \"%s\" | Out-String\n" % func)
        p.stdin.write("$b=[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(\"$a\"))\n")
        p.stdin.write("Write-Host \"[BEGIN]\"\n")
        p.stdin.write("Write-Host $b\n")

        # begin flag used to remove possible bullshit output print before the func is launched
        if '[BEGIN]' in p.stdout.readline():
            # Get the result in base64
            for i in p.stdout.readline():
                output += i
            output = base64.b64decode(output)
    except Exception:
        pass

    return output
