Auto_StartSSL
============

A tool to quickly generate multiple (free) StartCom StartSSL certificates

## Disclaimer

This fork of StartSSL_API is NOT about creating an API, this is my dumbed down version of it that can generate you startssl certificates fast. If you want to improve something, contribute upstream. I only refactored most of the code that is still in this repo and streamlined things, credit goes to <a href=https://github.com/max-weller/StartSSL_API>Max Weller</a>

Also, if this breaks your your computer, microwave, cat, or startssl account, you're on your own…

## HowTo

Follow these steps to get certificates for multiple subdomains at the same time:
Steps 1-4 you will have to do only once.

1. Get an account at startssl.com and complete Class 1 verification. It's free but you'll need a verifiable address
2. Export the client certificate you use to login to startSSL in your browser.
  * In Firefox: Edit -> Preferences -> Advanced -> Certificates -> View Certificates -> Your Certificates tab -> click your cert under StartCom Ltd. -> Backup…
  * This will ask you for a password. Choose anything that you can remember for a few minutes (You'll only need it only once the first time you do step 5).
  * Note that after you entered the password in step 5 and everything worked there will be a `cert.pem` file that contains your unencrypted private key for startssl. You might consider deleting this file again after you got your certificates.
3. Edit the PKCS12 variable (this is the only variable you need to touch) in config.py and point it to the file you exported from Firefox.
4. The top-level domains you want certificates for need to be verified. If they aren't already, see **Domain Validation** for this (or do it manually at startssl.com).

5. Generate your certificates
 * If you just want a single subdomain certificate, run this and you're done
 ```
 ./startssl_certify.py --oneshot SUBDOMAIN.DOMAIN
 ```
 * If you want to generate certs for multiple subdomains at once, follow the instructions under **Certification**.

## Domain Validation

To see a list of all domains you have validated in your account, run:
```
./startssl_get_valids.py
```

To start validation process of another domain, for the domain **example.com** do this:
```
./startssl_validate.py example.com
```

It will ask if you are sure to run validation. Answer with 'y'.

An email with the validation code will be sent to postmaster@example.com. Paste the validation code to the prompt shown by the validate script.

Note: At the moment it is not possible to choose the mail address, the first one will be always used.

If the script is cancelled in between, run it again with the previously displayed token, like this:
```
./startssl_validate.py example.com 1234567
```

## Certification

To generate certificates, edit `domains.txt` and put in all domain and subdomain names
you want to have certificates for. It has to look like this:
```
example.org
some-subdomain.example.org
some-other-subdomain.example.org
```

Afterwards, run:
```
./startssl_certify.py --multiple
```

A new 4096-bit RSA private key will be generated for each subdomain. The CSR will be generated automatically from the private key and uploaded to startssl. You will get a SUBDOMAIN.DOMAIN_privatekey.pem and SUBDOMAIN.DOMAIN_cert.pem file for each subdomain you entered in the file.

If a cert is withheld for manual approval (because you picked a weird subdomain like `test`), you can retrieve it later like this:

```
./startssl_get_certs.py
```
Displays a list of all your certificates, first column is the ID.


```
./startssl_get_certs.py 1234567 > somename_cert.py
```
to download it


