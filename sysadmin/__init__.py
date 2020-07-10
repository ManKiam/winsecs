from . import (
    apachedirectorystudio, coreftp, cyberduck, filezilla, filezillaserver,
    ftpnavigator, iisapppool, iiscentralcertp, keepassconfig, opensshforwindows,
    openvpn, puttycm, rdpmanager, unattended, vnc, winscp, wsl
)

modules = {
    **apachedirectorystudio.modules, **coreftp.modules, **cyberduck.modules, **filezilla.modules,
    **filezillaserver.modules, **ftpnavigator.modules, **iisapppool.modules, **iiscentralcertp.modules,
    **keepassconfig.modules, **opensshforwindows.modules, **openvpn.modules, **puttycm.modules,
    **rdpmanager.modules, **unattended.modules, **vnc.modules, **winscp.modules, **wsl.modules
}
