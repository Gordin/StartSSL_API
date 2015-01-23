#!/usr/bin/python
import subprocess
import re
import urllib

from config import STARTSSL_BASEURI


def get_valids():
    VALIDATED_RESSOURCES = re.compile(
        '<td nowrap>(?P<resource>.+?)</td><td nowrap> ' +
        '<img src="/img/yes-sm.png"></td>')

    params = [('app', 12)]
    curl_command = "curl -b \"$(cat startssl_cookie.txt)\" --data '%s' -s \"%s\""\
        % (urllib.urlencode(params), STARTSSL_BASEURI)
    output = subprocess.check_output(curl_command, shell=True)

    items = VALIDATED_RESSOURCES.finditer(output)
    valids = []
    for item in items:
        print(item.group(1))
        valids.append(item.group(1))
    return valids

if __name__ == '__main__':
    get_valids()
