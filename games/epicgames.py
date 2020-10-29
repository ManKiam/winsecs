# -*- coding: utf-8 -*-
import os


class EpicGames:
    def run(self, profile):
        x = '{LOCALAPPDATA}\\EpicGamesLauncher\\Saved\\Config\\Windows\\GameUserSettings.ini'.format(**profile)
        if os.path.isfile(x):
            return x


modules = {"EpicGames": EpicGames()}
