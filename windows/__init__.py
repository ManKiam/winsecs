from . import (
    autologon, cachedump, credfiles, credman, hashdump,
    lsa_secrets, mkfiles, ppypykatz, vault, vaultfiles, winpwd
)

modules = {
    **autologon.modules, **cachedump.modules, **credfiles.modules, **credman.modules,
    **hashdump.modules, **lsa_secrets.modules, **mkfiles.modules, **ppypykatz.modules,
    **vault.modules, **vaultfiles.modules, **winpwd.modules
}
