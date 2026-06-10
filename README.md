# siwx-go

[![CI](https://github.com/anitconsultant/siwx-go/actions/workflows/ci.yml/badge.svg)](https://github.com/anitconsultant/siwx-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/anitconsultant/siwx-go)](https://goreportcard.com/report/github.com/anitconsultant/siwx-go)
[![pkg.go.dev](https://pkg.go.dev/badge/github.com/anitconsultant/siwx-go.svg)](https://pkg.go.dev/github.com/anitconsultant/siwx-go)
[![License: Apache-2.0 / MIT](https://img.shields.io/badge/license-Apache--2.0%20%2F%20MIT-blue.svg)](LICENSE-APACHE)

**Let people log in to your Go app with a crypto wallet instead of a password.**

`siwx-go` checks that a wallet (like **Phantom** on Solana or **MetaMask** on
Ethereum) really signed a sign-in message. If the check passes, you know who the
user is — no password, no email, no third-party login button.

This follows the open standard [CAIP-122](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-122.md)
(the "Sign-In With X" idea), built on
[Sign-In With Ethereum](https://eips.ethereum.org/EIPS/eip-4361) and the
[Phantom Sign-In With Solana](https://github.com/phantom/sign-in-with-solana) spec.

---

## Table of contents

- [Why use this?](#why-use-this)
- [How it works (the big picture)](#how-it-works-the-big-picture)
- [Install](#install)
- [Which package do I use?](#which-package-do-i-use)
- [Example 1: Solana only (the `siws` package)](#example-1-solana-only-the-siws-package)
- [Example 2: Solana and Ethereum (the `siwx` package)](#example-2-solana-and-ethereum-the-siwx-package)
- [What you get back: the `Identity`](#what-you-get-back-the-identity)
- [Handling errors](#handling-errors)
- [Build a real login server (the demo hub)](#build-a-real-login-server-the-demo-hub)
- [The browser side](#the-browser-side)
- [Protect your routes with a token](#protect-your-routes-with-a-token)
- [Configuration](#configuration)
- [Security](#security)
- [Where to look in this repo](#where-to-look-in-this-repo)
- [FAQ](#faq)
- [License](#license)

---

## Why use this?

A normal login asks for a username and password. You then have to store those
passwords safely, handle "forgot password" emails, and worry about leaks.

Wallet sign-in is different. The user already has a wallet that holds a secret
key. To log in, they **sign a short message** with that key. Your server checks
the signature. If it matches, the user proved they own that wallet — and you
never had to store a password.

`siwx-go` does the hard part: reading the message and checking the signature in
a safe, correct way.

---

## How it works (the big picture)

Signing in takes five steps. Your server and the user's wallet pass a message
back and forth:

```
  Browser / Wallet                         Your Go server
  ----------------                         --------------
  1. "I want to log in"     ──────────▶    Make a one-time code (a "nonce")
                            ◀──────────     Send the code back
  2. Wallet signs a message
     that includes the code
  3. Send message + signature ────────▶    Check it with siwx-go
                                           ✓ domain is mine
                                           ✓ code is fresh (not reused)
                                           ✓ not expired
                                           ✓ signature is real
                            ◀──────────     4. Give back a login token (JWT)
  5. Use the token on later requests ─▶     Token says who you are
```

A few words you'll see a lot:

- **Nonce** — a one-time code your server hands out. It stops someone from
  reusing an old signed message (a "replay"). Use each nonce once, then throw it
  away.
- **Domain** — your site's name, like `app.example.com`. The signed message
  names a domain, and your server checks it matches yours.
- **CAIP-2 chain id** — a short text label for a blockchain, like
  `solana:mainnet` or `eip155:1` (Ethereum mainnet).

---

## Install

```bash
go get github.com/anitconsultant/siwx-go
```

Requires **Go 1.24+**.

---

## Which package do I use?

This repo gives you two packages. Pick one:

| You want… | Use | Why |
|-----------|-----|-----|
| **Solana only**, with zero extra dependencies | [`siws`](siws/) | Pure Go standard library. Small and simple. |
| **Solana and Ethereum** (or room to add more chains) | [`siwx`](siwx/) | One front door for many chains. |

If you start with Solana and later add Ethereum, you can move from `siws` to
`siwx` without rewriting your whole app — `siwx` uses `siws` under the hood.

---

## Example 1: Solana only (the `siws` package)

Say your web page already collected two things from the wallet:

- `rawMessage` — the **exact bytes** of the text the wallet signed.
- `signature` — the 64-byte signature the wallet gave back.

Here is the whole check:

```go
package main

import (
	"fmt"

	"github.com/anitconsultant/siwx-go/siws"
)

func verifySolana(rawMessage, signature []byte, myNonce string) {
	result, err := siws.VerifyRaw(rawMessage, signature, siws.VerifyOpts{
		ExpectedDomain: "app.example.com", // must match your site
		ExpectedNonce:  myNonce,           // the one-time code you handed out
		// Now is optional — leave it out to use the real clock.
	})
	if err != nil {
		// See the "Handling errors" section for what each one means.
		fmt.Println("sign-in failed:", err)
		return
	}

	// Success! The wallet really signed this.
	fmt.Println("signed in as:", result.Address) // base58 wallet address
	fmt.Println("for domain:", result.Domain)
}
```

`VerifyRaw` checks **everything in the right order** and only says "yes" if the
message names your domain, carries the nonce you expected, has not expired, and
the signature is real.

> **Tip:** Always pass the *original* bytes the wallet signed to `VerifyRaw`.
> Do not rebuild the message yourself — even a tiny difference (an extra space,
> a different date format) would make a valid signature look invalid.

---

## Example 2: Solana and Ethereum (the `siwx` package)

`siwx` lets you support more than one blockchain with the same code. You set it
up once, then verify by chain id.

```go
package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/anitconsultant/siwx-go/siwx"
	"github.com/anitconsultant/siwx-go/siwx/evm"    // Ethereum + EVM chains
	"github.com/anitconsultant/siwx-go/siwx/solana" // Solana
)

// Build this ONCE at startup and reuse it.
func newRegistry() siwx.VerifierRegistry {
	reg := siwx.NewRegistry()
	reg.Register(solana.New()) // handles "solana:..."
	reg.Register(evm.New())    // handles "eip155:..."
	return reg
}

func verify(reg siwx.VerifierRegistry, chainIDText string, message, signature []byte, myNonce string) {
	// Turn "solana:mainnet" or "eip155:1" into a chain id value.
	chainID, err := siwx.ParseCAIP2(chainIDText)
	if err != nil {
		fmt.Println("bad chain id:", err)
		return
	}

	id, err := reg.Verify(context.Background(), chainID, message, signature, siwx.VerifyOpts{
		ExpectedDomain: "app.example.com",
		ExpectedNonce:  myNonce,
	})
	if err != nil {
		if errors.Is(err, siwx.ErrUnsupportedNamespace) {
			fmt.Println("we don't support that chain yet")
		} else {
			fmt.Println("sign-in failed:", err)
		}
		return
	}

	fmt.Println("account:", id.Account.String())
	// solana:mainnet:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
	// eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B
}
```

To add another chain later, you write one small adapter and call
`reg.Register(...)`. The rest of your code does not change.

---

## What you get back: the `Identity`

When `siwx` verification succeeds, you get an `*siwx.Identity`. It holds the
facts you can trust about the user:

```go
type Identity struct {
	Account   CAIP10     // who: chain + address, e.g. solana:mainnet:7xKX...
	Domain    string     // the site name from the message
	Nonce     string     // the one-time code that was used
	IssuedAt  time.Time  // when the message was made
	ExpiresAt *time.Time // when it stops being valid (may be nil)
}
```

The most useful field is `Account`. Call `id.Account.String()` to get a stable
id you can save in your database, like
`eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B`.

(The `siws` package returns a `*siws.Message` instead, with fields like
`result.Address`, `result.Domain`, and `result.Nonce`.)

---

## Handling errors

Both packages return **named errors** so you can tell exactly what went wrong.
Check them with `errors.Is`:

```go
import "errors"

_, err := reg.Verify(ctx, chainID, message, signature, opts)
switch {
case err == nil:
	// success
case errors.Is(err, siwx.ErrNonceMismatch):
	// wrong, missing, or reused one-time code
case errors.Is(err, siwx.ErrExpired):
	// the message is too old
case errors.Is(err, siwx.ErrBadSignature):
	// wrong key, or the message was changed after signing
default:
	// something else — treat as "login failed"
}
```

What each error means, in plain words:

| Error | What happened |
|-------|---------------|
| `ErrMalformed` | The message could not be read. It was the wrong shape. |
| `ErrDomainMismatch` | The site name in the message is not yours. |
| `ErrNotYetValid` | The message says "not valid until" a future time. |
| `ErrExpired` | The message is past its expiry time. |
| `ErrNonceMismatch` | The one-time code is wrong, missing, or already used. |
| `ErrBadSignature` | The signature does not match the message or the wallet. |
| `ErrUnsupportedNamespace` | (`siwx` only) No chain adapter is registered for that chain id. |

The same names exist in both packages (`siws.ErrExpired` and `siwx.ErrExpired`,
and so on).

> **Good habit:** show users a simple "sign-in failed, please try again"
> message. Don't show the raw error — the library is careful never to leak
> secret data, and you should be too.

---

## Build a real login server (the demo hub)

You don't have to wire all this up from scratch. This repo ships a **complete,
runnable example server** in [`examples/hub/`](examples/hub/). Run it:

```bash
go run ./examples/hub
# Open http://localhost:8081 in a browser that has Phantom or MetaMask.
```

Click **Sign in with Phantom** or **Sign in with MetaMask** and watch the five
steps light up.

The hub shows the full flow and these routes:

| Method | Path | What it does |
|--------|------|--------------|
| `GET` | `/auth/nonce` | Hands out a fresh one-time code and sets it in a secure cookie. |
| `GET` | `/config` | Tells the web page what statement, chain, and expiry to use. |
| `POST` | `/auth/verify` | Checks the signed message and returns a login token (JWT). |
| `POST` | `/auth/link` | Adds another wallet to an existing account (needs a token). |
| `GET` | `/.well-known/jwks.json` | The public key others use to check your tokens. |
| `GET` | `/me` | A protected page that needs a valid token. |
| `GET` | `/metrics` | Simple plain-text counters. |
| `GET` | `/healthz` | Returns `ok` when the server is up. |

**One important detail the hub gets right:** the server hands out the nonce in
an `HttpOnly` cookie and reads the *expected* nonce from that cookie — not from
the message the user sends. That keeps the nonce check honest and blocks replay
attacks. See the handlers in [`examples/hub/handlers.go`](examples/hub/handlers.go).

---

## The browser side

The matching web page is in [`examples/web/`](examples/web/). It is plain
JavaScript with no build step, so it's easy to read and copy:

- [`examples/web/app.js`](examples/web/app.js) — the sign-in flow: get a nonce,
  ask the wallet to sign, send the result to `/auth/verify`. It supports both
  Phantom (Solana) and MetaMask (Ethereum), and uses
  [EIP-6963](https://eips.ethereum.org/EIPS/eip-6963) so it picks the right
  wallet when the user has several installed.
- [`examples/web/index.html`](examples/web/index.html) — the page with the two
  sign-in buttons.

For a step-by-step manual test (install a wallet, click, sign), see
[`examples/web/README.md`](examples/web/README.md).

---

## Protect your routes with a token

After sign-in, the hub gives the browser a **JWT** (a signed login token). You
attach that token to later requests, and a small middleware checks it. The
example middleware lives in [`examples/middleware/`](examples/middleware/):

```go
import hubmw "github.com/anitconsultant/siwx-go/examples/middleware"

// jwksURL points at /.well-known/jwks.json, which holds the public key.
r.GET("/me", hubmw.JWTAuth(jwksURL, issuerURL, audience), hubmw.GetMe)
```

`JWTAuth` checks the token on the way in. If the token is good, your handler
runs; if not, the request is rejected before it reaches your code. `GetMe` is a
tiny example handler that returns the signed-in user.

---

## Configuration

The demo server reads its settings from the environment, so you can change them
without touching code. The easiest way is a `.env` file:

```bash
cp .env.example .env   # then edit .env
go run ./examples/hub
```

Real environment variables always win over the `.env` file. The most useful
settings:

| Variable | Default | Meaning |
|----------|---------|---------|
| `SIWX_DOMAIN` | `localhost` | Your site's host name (no port). |
| `SIWX_PORT` | `8081` | The port the server listens on. |
| `SIWX_STATEMENT` | `Sign in to siwx-go demo` | The sentence shown in the wallet pop-up. |
| `SIWX_SOLANA_CHAIN` | `mainnet` | Which Solana cluster to name in the message. |
| `SIWX_SESSION_TTL_MIN` | `10` | How many minutes a sign-in message stays valid. |

The full list, with comments, is in [`.env.example`](.env.example). A longer
table is in [`examples/web/README.md`](examples/web/README.md).

---

## Security

This library is built to be careful by default. The `siws` core:

- **Checks things in the safest order:** parse → domain → not-before → expiry →
  nonce → signature. Cheap checks fail fast; the expensive signature check runs
  last.
- **Compares the nonce in constant time** (`crypto/subtle`) to avoid timing leaks.
- **Never lets a bad message reach the signature step** — sizes and shapes are
  checked first, so `ed25519.Verify` only sees well-formed input.
- **Never logs secret or attacker-controlled data.** Error messages name the
  field that failed, never its value.
- **Bounds its input** so a giant message can't be used to slow the server down.

Want the details?

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — what we defend against and how.
- [`docs/SECURITY.md`](docs/SECURITY.md) — how to report a vulnerability.
- [`docs/SECURITY_REVIEW_v0.1.0.md`](docs/SECURITY_REVIEW_v0.1.0.md) — a full
  review pass with every finding and its fix.

---

## Where to look in this repo

| Folder | What's inside |
|--------|---------------|
| [`siws/`](siws/) | Solana message parsing + Ed25519 checking. Zero dependencies. |
| [`siwx/`](siwx/) | The multi-chain layer (registry + `solana`/`evm` adapters). |
| [`examples/hub/`](examples/hub/) | A complete login server you can run. |
| [`examples/web/`](examples/web/) | The browser sign-in page (Phantom + MetaMask). |
| [`examples/middleware/`](examples/middleware/) | JWT check middleware for protected routes. |
| [`docs/`](docs/) | Threat model, security policy, and the review report. |

---

## FAQ

**Do I need a database?**
The library does not need one. A real app should store nonces and user accounts
somewhere. The demo hub keeps them in memory so it's easy to run; swap that for
a real store in production.

**Does the user pay any gas or send a transaction?**
No. Signing a message is free and happens entirely in the wallet. Nothing is
sent to the blockchain.

**Can I support a chain that isn't Solana or Ethereum?**
Yes. Write a small adapter that implements the `siwx.Verifier` interface and
register it with `reg.Register(...)`. Your app code stays the same.

**Why does the wallet show a warning on `localhost`?**
Some wallets warn on plain `http://localhost` because it isn't HTTPS. That's
expected for local testing — sign-in still works. The warning goes away on a
real `https://` site.

---

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT). You may
choose either license.
