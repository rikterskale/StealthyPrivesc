# Pull Request

## Summary

<!-- What changed and why? -->

## Safety impact

- [ ] Default enumeration behavior is unchanged or explicitly documented.
- [ ] No credentials, private keys, host data, or generated binaries are included.
- [ ] Any write, network, or process-spawning behavior is documented and tested.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Documentation updated where needed
