# Java Client

The command line client connects to the hidden service.

## Launching the Client

In order to work correctly, the client has to be launched with sockets configured for usage with Tor:

`java -jar anonionmail.jar -DsocksHost=127.0.0.1 -DsocksPort=9050`

The easiest and probably most secure way to do this is via the [Tails](https://tails.boum.org/) live OS.
