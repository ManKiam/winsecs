from . import dbvis, postgresql, robomongo, sqldeveloper, squirrel

modules = {**dbvis.modules, **postgresql.modules, **robomongo.modules, **sqldeveloper.modules, **squirrel.modules}
