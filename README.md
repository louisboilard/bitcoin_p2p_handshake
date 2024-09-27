# Bitcoin P2P Handshake Protocol Implementation

Based on the [doc](https://developer.bitcoin.org/reference/p2p_networking.html).

NOTE: This CLI uses a default dns-seed which may or may not respond.
Feed a specific seed via the `dns_seed` arg, a list of the hardcoded ones can be
found [here](https://github.com/bitcoin/bitcoin/blob/1b2460bd5824170ab85757e35f81197199cce9d6/src/chainparams.cpp#L112).

See options via `--help`.

You can quickly test that it returns nodes with tools such as dig/nslookup, i.e:
```
$ dig "dnsseed.bitcoin.dashjr.org" +short
$ nslookup "dnsseed.bitcoin.dashjr.org"
```

This is purely for testing/investigation purposes, but can be used as a base to
expend on (i.e implement more functionalities of the p2p network).

### Handshake

The handshake is implemented through a state machine where state transitions happen via
an implementation of the iter trait.

This allows potentially adding/removing transition steps internally without having to change
the public interface (see `Handshake::process()`). The iterator is consumed and
stops if it encounters an error or if the handshake is completed.

This is a simple way to formalize the handshake and to keep tack of the state of
the handshake at any moment.

The handshake contains the following steps (post connection with a peer, which
happens in the main fn):

1. Send a "version" message.
2. Recv a "version" message.
3. Send a "verack" message.
4. Recv a "verack" message.
5. Handshake is complete.

See the doc (i.e cargo doc --open) for specifications.
