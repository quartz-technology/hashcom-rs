# <h1 align="center"> hashcom-rs </h1>

<p align="center">
    <img src="https://github.com/quartz-technology/hashcom-rs/blob/main/.github/assets/COVER.PNG" width="400" alt="A DALL-E representation of a 
photo of a computer circuit in cyberpunk style with a dark theme">
</p>

<p align="center">
⚡️ A fast, minimal but yet extensible framework for building and using hash commitment schemes in Rust ⚡️
</p>

Cover by [DALL-E](https://openai.com/dall-e-2/).

## Introduction

[Commitment schemes](https://en.wikipedia.org/wiki/Commitment_scheme) are very powerful
cryptographic primitives used in many existing solutions.

I was inspired by the [go-ibft](https://github.com/0xPolygon/go-ibft) to create a framework to
easily integrate and customize a hash commitment scheme in a rust application.

This package exposes both a trait for you to build your scheme given a specific hash function, or
use an existing one.

## Architecture

The `hashcom-rs` library exposes a [`HashCommitmentScheme`](./src/lib.rs#L20) trait that can be
implemented with you own hash function.
You'll just have to implement the `commit` and `verify` methods.

A [`SHA256`](./src/lib.rs#L34) implementation is already provided. Below is an example of how it can be used
(here, there's only one party who acts as both the prover and the verifier):
```rust
/// Here, one party acts as both the prover and the verifier,
/// assuming that the verifier is not malicious.
fn it_verifies_valid_commitment() {
    let s: [u8; 4] = [52, 50, 52, 50]; // 4242 in string format.
    let r: [u8; 4] = [50, 52, 50, 52]; // 2424 in string format.

    // Commit phase.
    let party = SHA256Commitment::new(&s, &r);
    let commit = party.commit();

    // Verification phase.
    let verification = party.verify(&commit.unwrap(), &s, &r);

    assert_eq!(verification.is_ok(), true);
    assert_eq!(verification.unwrap(), true)
}
```

## Authors
Made with ❤️ by 🤖 [0xpanoramix](https://github.com/0xpanoramix/) 🤖
