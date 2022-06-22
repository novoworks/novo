Novo
=====================
Setup
---------------------
Novo is an implementation of a node for the Novo network and is one of the pieces of software that provide
the backbone of the network. It downloads and stores the entire history of Novo transactions; depending on the speed
of your computer and network connection, the synchronization process can take anywhere from a few minutes to a hour or more.

To download Novo, visit [novo.org](https://novonode.org/).

Running
---------------------
Novo is only supported on the Linux and docker platforms at this time.

To run Novo on Linux:

* unpack the files into a directory
* run `bin/novod`

### Need Help?

* Log an issue on [GitHub] (https://github.com/novoworks/novo/issues)
* Ask for help on the [Novo Forum](https://novoforum.net/).
* Consult [Novo Wiki](https://wiki.novonode.org/) for information about Novo protocol.

Building
---------------------
The following are developer notes on how to build Novo. They are not complete guides, but include notes on the
necessary libraries, compile flags, etc.

- [Unix Build Notes](build-unix.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The Novo repo's [root README](/README.md) contains relevant information on the development process and automated
testing.

- [Developer Notes](developer-notes.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [Travis CI](travis-ci.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)


### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
This product includes software developed by the Bitcoin developers for use in [Dogecoin Core](https://www.bitcoin.org/).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
