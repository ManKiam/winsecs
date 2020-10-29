from . import (
    autologon, registry_secrets, credfiles, credman,
    lsa_secrets, mkfiles, vault, vaultfiles, wifi
)

modules = {
    **autologon.modules, **registry_secrets.modules, **credfiles.modules, **credman.modules,
    **lsa_secrets.modules, **mkfiles.modules, **vault.modules, **vaultfiles.modules, **wifi.modules
}
