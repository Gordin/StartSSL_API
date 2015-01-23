#!/usr/bin/python
import subprocess
import re
import os
import sys
from getpass import getpass
from subprocess import Popen, PIPE, STDOUT
from config import PKCS12, CERTFILE


def auth():
    if not os.path.isfile(CERTFILE):
        if not os.path.isfile(PKCS12):
            sys.exit("You need a pkcs12 or pem file.")
        password = getpass("Enter the password for the pkcs12 file: ")
        convert_command = "openssl pkcs12 -in '%s' -out '%s' -nodes -passin stdin"\
            % (PKCS12, CERTFILE)
        p = Popen(convert_command, stdin=PIPE, stdout=PIPE, stderr=STDOUT,
                  shell=True)
        output = p.communicate(input=password)[0]
        p.stdin.close()
        if p.wait() != 0:
            print("Something went wrong. cert and key NOT exported:")
            os.remove(CERTFILE)
            sys.exit(output)
        else:
            print("Cert and key exported to %s" % CERTFILE)
    auth_command = "curl --cert \"%s\" -d app=11 -si https://auth.startssl.com"\
        % (CERTFILE)
    output = subprocess.check_output(auth_command, shell=True)
    # print output
    m = re.search(r"STARTSSLID=[a-zA-Z0-9]+", output)
    if not m:
        print("Error")
        os.exit(1)

    token = m.group()
    # print("Auth Token: ", token)
    print("Getting Auth Token successful")
    with open('startssl_cookie.txt', 'w') as outfile:
        outfile.write(token)

if __name__ == '__main__':
    auth()
