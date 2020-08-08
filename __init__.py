__version__ = 1

from . import (
    browsers, chats, databases, games, git,
    mails, maven, memory, multimedia, php, svn,
    sysadmin, wifi, windows
)

modules = {
    'browsers': browsers.modules, 'chats': chats.modules,
    'databases': databases.modules, 'games': games.modules,
    'git': git.modules, 'mails': mails.modules,
    'maven': maven.modules, 'memory': memory.modules,
    'multimedia': multimedia.modules, 'php': php.modules,
    'svn': svn.modules, 'sysadmin': sysadmin.modules,
    'wifi': wifi.modules, 'windows': windows.modules
}


# all_modules = {
#     **browsers.modules, **chats.modules, **databases.modules, **games.modules,
#     **git.modules, **mails.modules, **maven.modules, **memory.modules, **multimedia.modules,
#     **php.modules, **svn.modules, **sysadmin.modules, **wifi.modules, **windows.modules
# }
