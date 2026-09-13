## `bernstein bench` bundles are now actually signature-checked

`AgentCardSigner.sign` imported `bernstein.core.identity.agent_card_signer`,
a module that does not exist, so every production `bernstein bench run`
(without `--stub-signer`) silently caught the `ImportError` and signed with
`StubSigner`'s public test key instead. `BenchVerifier.verify` never
checked `signature`/`signer_fingerprint` at all, so a bundle's "signed"
claim was decorative either way.

`AgentCardSigner` now signs a detached Ed25519 JWS off the install identity
(mirroring `reliability.InstallIdentityReliabilitySigner`), and `bench
verify` rejects a bundle whose signature does not verify, with a new
`--signer-key` option to pass trusted install-identity public keys
(mirroring `bench reliability-verify`).
