#!/usr/bin/python
import subprocess
import re
import sys
import os.path
import tempfile
import urllib
import os

from config import STARTSSL_BASEURI, VALIDATED
from startssl_get_valids import get_valids
from startssl_auth import auth

cert_type = "server"
privkey_suffix = "_privatekey.pem"
cert_suffix = "_cert.pem"
rootca = "ca.pem"
class1 = "sub.class1.server.ca.pem"


def get_startssl_certs():
    startssl_certs = "http://www.startssl.com/certs/"
    subprocess.check_output("curl %s -O" % (startssl_certs + rootca),
                            shell=True)
    subprocess.check_output("curl %s -O" % (startssl_certs + class1),
                            shell=True)


def add_intermediates(cert_filename):
    with open(cert_filename, 'a') as outfile:
        with open(class1, 'r') as pem:
            pem_content = pem.read()
            outfile.write(os.linesep + pem_content)
        with open(rootca, 'r') as pem:
            pem_content = pem.read()
            outfile.write(pem_content)


def main(domain):
    auth()
    valids = get_valids()
    if not domain:
        domainlist_file = "domains.txt"
        if not os.path.isfile(domainlist_file):
            sys.exit("Domain list file %s doesn't exist" % domainlist_file)
        domains = get_domains(domainlist_file, valids)
    else:
        if domain.split(".", 1)[1] not in valids:
            sys.exit("Domain is not validated!")
        domains = [{"top": domain.split(".", 1)[1], "subs": [domain]}]
    get_startssl_certs()
    for domain in domains:
        top_domain = domain["top"]
        if not VALIDATED:
            for sub_domain in domain["subs"]:
                privkey_file, cert_file = generate_key(top_domain, sub_domain)
                csr_content = get_csr(privkey_file)
                token2 = second_step(csr_content)
                third_step(token2)
                fourth_step(token2, [top_domain], [sub_domain])
                fifth_step(token2, cert_file)
                add_intermediates(cert_file)
                print("Success! Saved cert at %s" % cert_file)
        else:
            privkey_file, cert_file = generate_key(top_domain, False)
            csr_content = get_csr(privkey_file)
            token2 = second_step(csr_content)
            third_step(token2)
            fourth_step(token2, [top_domain], domain["subs"])
            fifth_step(token2, cert_file)
            print("Success! Saved cert at %s" % cert_file)


def curl(params):
    curl_command =\
        "curl -b \"$(cat startssl_cookie.txt)\" --data '%s' -s \"%s\""\
        % (urllib.urlencode(params), STARTSSL_BASEURI)
    return subprocess.check_output(curl_command, shell=True)


def generate_key(domain, subdomain):
    if subdomain:
        privkey_file = subdomain + privkey_suffix
        cert_file = subdomain + cert_suffix
    else:
        privkey_file = domain + privkey_suffix
        cert_file = domain + cert_suffix
    if not os.path.isfile(privkey_file):
        print("Private key file %s doesn't exist, generating..."
              % privkey_file)
        os.system("openssl genrsa -out \"%s\" 4096" % privkey_file)
    if os.path.exists(cert_file):
        print("Certificate file %s already exists, refusing to overwrite!"
              % cert_file)
        return False
    return privkey_file, cert_file


def get_csr(privkey_file):
    print("Private key saved as %s" % privkey_file)
    print("Generating CSR from private key ...")
    tempcsr = tempfile.mktemp(".csr")
    os.system("openssl req -new -key \"%s\" -out \"%s\" -batch"
              % (privkey_file, tempcsr))

    # print("CSR path: %s" % tempcsr)

    with open(tempcsr, 'r') as content_file:
        csr_content = content_file.read()

    os.remove(tempcsr)

    return csr_content


def second_step(csr_content):
    CERT_TOKEN =\
        re.compile(r"x_third_step_certs\(\\'([a-z]+)\\',\\'([0-9]+)\\',")

    params = [('app', 12), ('rs', 'second_step_certs'), ('rst', ''),
              ('rsargs[]', cert_type), ('rsargs[]', csr_content)]
    output = curl(params)

    tokens = CERT_TOKEN.search(output)
    if tokens:
        token2 = tokens.group(2)
    else:
        print("Error in second step (submitting csr)")
        print(output)
        sys.exit(1)

    # print("Certification token: %s" % token2)

    return token2


def third_step(token2):
    params = [('app', 12), ('rs', 'third_step_certs'), ('rst', ''),
              ('rsargs[]', cert_type), ('rsargs[]', token2), ('rsargs[]', '')]
    curl(params)


def get_domains(domainlist_file, valid_domains):
    domains = [{"top": x, "subs": []} for x in valid_domains]
    with open(domainlist_file, 'r') as content_file:
        for line in content_file:
            line = line.strip()
            # print("Checking '%s'"%line)
            for domain in domains:
                # print("- ", domain)
                if line.endswith("." + domain["top"]):
                    domain["subs"].append(line)
                elif line == domain["top"]:
                    pass
                else:
                    sys.exit("Invalid domain requested: "+line)
    domains = [d for d in domains if len(d["subs"])]
    for domain in domains:
        print("Domain: %s with subdomains %s"
              % (domain["top"], domain["subs"]))
    return domains


def fourth_step(token2, top_domains, sub_domains):
    for domain in top_domains:
        params = [('app', 12), ('rs', 'fourth_step_certs'), ('rst', ''),
                  ('rsargs[]', cert_type), ('rsargs[]', token2),
                  ('rsargs[]', domain), ('rsargs[]', '')]
        curl(params)
        if not VALIDATED:
            break

    for domain in sub_domains:
        params = [('app', 12), ('rs', 'fourth_step_certs'), ('rst', ''),
                  ('rsargs[]', cert_type), ('rsargs[]', token2),
                  ('rsargs[]', ''), ('rsargs[]', domain)]
        curl(params)
        if not VALIDATED:
            break


def fifth_step(token2, cert_file):
    params = [('app', 12), ('rs', 'fifth_step_certs'), ('rst', ''),
              ('rsargs[]', cert_type), ('rsargs[]', token2), ('rsargs[]', ''),
              ('rsargs[]', '')]
    output = curl(params)

    if "We have gathered enough information" not in output:
        sys.exit("Error in fifth step: "+output)

    params = [('app', 12), ('rs', 'sixth_step_certs'), ('rst', ''),
              ('rsargs[]', cert_type), ('rsargs[]', token2)]
    output = curl(params)

    REQUEST_CERTIFICATE_CERT = re.compile(
        '<textarea.*?>(?P<certificate>.*?)</textarea>')

    m = REQUEST_CERTIFICATE_CERT.search(output)
    if m:
        cert = m.group("certificate").replace("\\n", "\n")

        with open(cert_file, 'w') as outfile:
            outfile.write(cert)
    else:
        sys.exit("Error in last step: "+output)

if __name__ == '__main__':
    if sys.argv[1] != "--multiple":
        if len(sys.argv) == 3 and sys.argv[1] == "--oneshot":
            main(sys.argv[2])
            sys.exit(0)
        else:
            print("Invalid command line params")
            sys.exit(5)
    main(False)
