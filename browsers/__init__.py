from . import chromium, mozilla, ie

modules = {**chromium.modules, **mozilla.modules, **ie.modules}
