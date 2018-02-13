# `p751sidh`

The `p751sidh` package provides a Go implementation of  (ephemeral)
supersingular isogeny Diffie-Hellman, as described in [Costello-Longa-Naehrig 2016](https://eprint.iacr.org/2016/413).
Internal functions useful for the implementation are published
in the p751toolbox package.

The implementation is intended for use on the `amd64` architecture only -- no
generic field arithmetic implementation is provided.  Portions of the field
arithmetic were ported from the Microsoft Research implementation.

This package follows their naming convention, writing "Alice" for the party
using 2^e-isogenies and "Bob" for the party using 3^e-isogenies.

This package does NOT implement SIDH key validation, so it should only be
used for ephemeral DH.  Each keypair should be used at most once.

If you feel that SIDH may be appropriate for you, consult your
cryptographer.

Special thanks to [Craig Costello](http://www.craigcostello.com.au/), [Diego Aranha](https://sites.google.com/site/dfaranha/), and [Deirdre Connolly](https://twitter.com/durumcrustulum) for advice
and discussion.

