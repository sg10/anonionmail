
# Hidden Service Proxy Setup

For the hidden service, we use a clean Debian 8.5 (jessie) installation in Virtual Box and installed Tor via the repositories.

The Proxy acts as a middle-man between our Java Client and the Google App Engine service running the Python mail server.

## Configuration of the Hidden Service

The contents of `/etc/tor/torrc` look like this:

`DataDirectory /var/lib/tor`
`HiddenServiceDir /var/lib/tor/hidden_service/`
`HiddenServicePort 80 localhost:8087`

## Setup of the SSL tunnel


