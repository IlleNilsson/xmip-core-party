# xmip-core-party

The Party: the actor Xmip recognizes, per ADR-0007 and ADR-0008, and the
identities it is recognized by on receive and presents on send. One registry,
both directions.

A Party is not a credential store and not a role. Its identities are how it
is recognized; a role is granted separately (ADR-0009). The vocabulary of an
identity lives in `xmip-core`, because the three gates need it and none of
them may depend on the Party.

ADR-0019 governs identity in both directions; `doc/terminology.md`, *Identity,
Party and direction*, is the vocabulary. `architecture.toml` carries the
maturity.
