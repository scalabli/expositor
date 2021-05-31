
from os import path

if path.exists(path.expanduser("~/.expositor")):
    EXPOSITOR_CONFIG_DIR = '~/.expositor/'
else:
    EXPOSITOR_CONFIG_DIR = "~/.config/expositor/"

COLORIZE_FIELDS = {
    'ip_str': 'green',
    'port': 'yellow',
    'data': 'white',
    'hostnames': 'magenta',
    'org': 'cyan',
    'vulns': 'red',
}
