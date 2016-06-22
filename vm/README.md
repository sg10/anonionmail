
# Hidden Service Proxy Setup

The Proxy acts as a middle-man between our Java Client and the Google App Engine service running the Python mail server. For the hidden service, we use a clean Debian 8.5 (jessie) installation in Virtual Box and installed Tor via the repositories. 

## Setup of the SSL forwarding

A simple request forwarder for HTTPS is insufficient. The GAE domain uses a (wildcard) SSL certificate, which on validation checks the domain the request comes from. With the request coming from a `.onion` domain, validation fails. Since transmission over the Tor network itself is encrypted anyway, the hidden service receives common HTTP requests on port 80 and establishes a HTTPS connection to the GAE server itself. To achieve this, we use `stunnel4` (repositories) with the following configuration file `proxy.conf`:

```
[http2https]
client=yes
accept=0.0.0.0:8087
connect=ourgaedomain.appspot.com:443
renegotiation=yes
reset=yes
delay=yes
```

Launch with `stunnel4 proxy.conf`.

## Configuration of the Hidden Service

The contents of `/etc/tor/torrc` look like this:

```
DataDirectory /var/lib/tor
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 localhost:8087
```

## HTTP Host Field Issue

For making GAE requests, the HTTP `Host` header field has to match the GAE subdomain. Therefore, the Java client has to overwrite the `Host` field manually before sending the HTTP request.

## Different Approaches for the Hidden Service Proxy

* install Nginx web server and PHP with a simple script forwarding all Post data to GAE
* manipulate the machine's host file to redirect the requests
