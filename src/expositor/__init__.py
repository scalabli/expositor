"""
Shodan CLI

Note: Always run "shodan init <api key>" before trying to execute any other command!

A simple interface to search Shodan, download data and parse compressed JSON files.
The following commands are currently supported:

    alert
    convert
    count
    data
    download
    honeyscore
    host
    info
    init
    myip
    parse
    radar
    scan
    search
    stats
    stream

"""

from shodan.client import Shodan
from shodan.exception import APIError

__version__ = "2021.6.dev1"
