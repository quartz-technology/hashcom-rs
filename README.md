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