# Security policy

cunho signs credentials that people carry in their EU Digital Identity Wallet. We take reports about its security
seriously and handle them in confidence.

## Reporting a vulnerability

Please do not report security problems in public issues, pull requests or discussions.

Write to [paulo@foaap.app](mailto:paulo@foaap.app) with the subject "cunho security". If you want to send the details
encrypted, say so in a first message and we will agree a channel before you send them.

Include what you can of:

- the version or commit you tested, and how cunho was configured;
- what an attacker can do, and what they need to do it;
- the steps to reproduce it, or a proof of concept;
- whether and how you would like to be credited.

Test against your own deployment of cunho. Please do not test against demo.foaap.app or issuer.foaap.app, which are
public demonstrations, or against anyone else's deployment.

## What happens next

- We acknowledge your report within 3 business days.
- We confirm or rule out the problem, and tell you how serious we think it is, within 10 business days.
- We fix confirmed problems in the supported version, starting with the most serious, and keep you informed.
- We agree a disclosure date with you, normally when a fix is released, and credit you unless you prefer otherwise.

## Supported versions

The latest release receives security fixes. Customers with a commercial licence also receive fixes for the versions
their agreement covers.

## Scope

In scope: the issuer engine (`src/cunho/`), the demo service (`src/cunho_demo/`), the container kit (`deploy/`) and
the tools in this repository. Weaknesses in a dependency belong to that project, but tell us if cunho is exposed by
one and we will help.
