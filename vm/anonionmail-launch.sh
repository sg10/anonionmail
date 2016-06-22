#!/bin/bash

# -----
# this script can be used to easily download and start the script (e.g. within Tails)

if [ ! -f anonionmail.jar ]; then
  wget https://github.com/sg10/akits1-anonionmail/raw/master/client-tor.jar -O anonionmail.jar
fi

# start java app with sockets configured for Tor
java -jar anonionmail.jar -DsocksPort=9050 -DsocksHost=127.0.0.1
