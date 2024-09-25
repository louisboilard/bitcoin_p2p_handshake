# Bitcoin P2P Handshake Protocol Implementation

Based on the [doc](https://developer.bitcoin.org/reference/p2p_networking.html).

NOTE: This CLI uses a default dns-seed which may or may not respond.
Feed a specific seed via the `dns_seed` arg, a list of the hardcoded ones can be
found [here](https://github.com/bitcoin/bitcoin/blob/1b2460bd5824170ab85757e35f81197199cce9d6/src/chainparams.cpp#L112).

You can quickly test that it returns nodes with tools such as dig/nslookup, i.e:
```
$ dig "dnsseed.bitcoin.dashjr.org" +short
$ nslookup "dnsseed.bitcoin.dashjr.org"
```

This is purely for testing/investigation purposes, but can be used as a base to
expend on (i.e implement more functionalities of the p2p network).

### Handshake

The handshake has the following steps:

1. Get peers from a dns seed (the list of ip's can be obtained with the
   makeseeds script or using the bitcoin seeder).
2. Connect to a peer via tcp.
3. Send a "version" message to the peer.
4. Receive a "version" message from the peer.
5. Send/Recv a "verack" message.
6. Handshake is complete.
