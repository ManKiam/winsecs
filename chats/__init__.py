from . import pidgin, psi, skype, discord, telegram

modules = {**pidgin.modules, **psi.modules, **skype.modules, **discord.modules, **telegram.modules}
