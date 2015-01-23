StartSSL_API
============

A python/CLI API for some StartCom StartSSL functions

## HowTo

Follow these steps to get certificates for multiple subdomains at the same time:

1. Get an account at startssl.com and complete Class 1 verification. It's free but you'll need a verifiable address
2. Export the client certificate you use to login to startSSL in your browser.
In Firefox: Edit -> Preferences -> Advanced -> Certificates -> View Certificates -> Your Certificates tab -> click your cert under StartCom Ltd. -> Backup…
This will ask you for a password. Choose anything that you can remember for a few minutes (You'll only need it once).
3. Edit the PKCS12 variable in config.py and point it to the file you exported from Firefox.
4. The top-level domains you want certificates for need to be verified. See **Domain Validation** for this.
5. When your domains are verified, follow the instructions under **Certification**. You should have your certificates now.

## Authentication

To authenticate you need your StartSSL client certificate.

You may want to modify the `CERTFILE` in config.py to point to your client certificate and key. It should be a file in PKCS#12 file on Mac OS X, or a .pem file containing the client certificate and key, concatenated.

After that, run this command to log in:
```
./startssl_auth.py
```

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

### Example session transcript:

```
➜  StartSSL_API git:(master) ✗ ./startssl_validate.py luelistan.net
Going to start validatation process for domain "luelistan.net"
Continue? y
Validation session: 4534049
(0) postmaster@luelistan.net
(1) hostmaster@luelistan.net
(2) webmaster@luelistan.net
Using first address postmaster@luelistan.net
The code was sent to your mail address.
Validation Code from email: nx8DQBFI195xw2i9
Success
```

## Certification

To generate a certificate, create a file called `somename_domains.txt`. Put in all domain and subdomain names
you want to have in this certificate. If you have Class 1 certification, it has to look like this:
```
example.org
some-subdomain.example.org
some-other-subdomain.example.org
```

Afterwards, run:
```
./startssl_certify.py somename
```

If the file somename_SUBDOMAIN.DOMAIN_privatekey.pem does not exist, a new 4096-bit RSA private key will be generated. The CSR will be generated automatically from the private key and uploaded to startssl. If a certificate is returned by startssl, it is stored as somename_cert.pem. You will get a somename_SUBDOMAIN.DOMAIN_privatekey.pem and somename_SUBDOMAIN.DOMAIN_cert.pem file for each subdomain you entered in the file.

If it is withheld for manual approval, you can retrieve it later like this:

```
./startssl_get_certs.py
```
Displays a list of all your certificates, first column is the ID.


```
./startssl_get_certs.py 1234567 > somename_cert.py
```
to download it



## Usage
* Place startssl.conf in /etc or your current working directory
* Adjust the settings in startssl.conf
* Show all available certificates:
  * `startssl.py certs`
* Download a specific certificate
  * `startssl.py certs example.com`
* Download all new and missing certificates
  * `startssl.py certs --store new --store missing`
* Submit CSR files
  * `startssl.py csr example.com.csr mail.example.com.csr`
