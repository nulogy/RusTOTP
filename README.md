# RusTOTP

A simple Rust implementation of the Time-Based One Time Password (TOTP) and HMAC-based One-Time Password algorithms specified in [RFC 6238](https://tools.ietf.org/html/rfc6238), and [RFC 4226](https://tools.ietf.org/html/rfc4226), respectively.

# Usage

Build the command-line client from the rustotp_cli crate:

```
$ cd rustotp_cli
$ cargo build
```

Generate a single OTP from a key:

```
$ ./target/debug/totp-client 42
663792
```

Or, start an interactive session where a new OTP will be generated at every timestep, with a visual progress bar:

```
$ ./target/debug/totp-client 42 --timestep=5 --interactive
495515
#####
#####
783920
#####
#####
484936
#####
####
```
