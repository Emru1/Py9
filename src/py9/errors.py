from enum import StrEnum


class Errors(StrEnum):
    Ebadattach = 'unknown specifier in attach'
    Ebadoffset = 'bad offset'
    Ebadcount = 'bad count'
    Ebotch = '9P protocol botch'
    Ecreatenondir = 'create in non-directory'
    Edupfid = 'duplicate fid'
    Eduptag = 'duplicate tag'
    Eisdir = 'is a directory'
    Enocreate = 'create prohibited'
    Enomem = 'out of memory'
    Enoremove = 'remove prohibited'
    Enostat = 'stat prohibited'
    Enotfound = 'file not found'
    Enowrite = 'write prohibited'
    Enowstat = 'wstat prohibited'
    Eperm = 'permission denied'
    Eunknownfid = 'unknown fid'
    Ebaddir = 'bad directory in wstat'
    Ewalknodir = 'walk in non-directory'
