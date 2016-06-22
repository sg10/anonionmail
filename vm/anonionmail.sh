#!/bin/bash

if [ ! -f anonionmail.jar ]; then
  wget https://github.com/sg10/akits1-anonionmail/raw/master/client-tor.jar -O anonionmail.jar
fi

java -jar anonionmail.jar -DsocksPort=9050 -DsocksHost=127.0.0.1
