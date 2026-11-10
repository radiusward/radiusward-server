# ADR 0048: More stored password formats

Status: Accepted (2026-11-10). Phase 5, work package 5.24 ([plans/phase-5-auth.md](../plans/phase-5-auth.md)). Extends
[ADR 0021](0021-identity-stores.md).

## Context
PAP checked cleartext, SHA-crypt, bcrypt, salted SHA, PBKDF2 and NT hashes. A user stored with any other hash was
rejected. That blocks migrations:
- current Linux distributions hash with **yescrypt** (`$y$`, libxcrypt's default);
- older systems and LDAP directories hold **MD5-crypt** (`$1$`), MD5, salted MD5 and unsalted SHA;
- old Windows data holds **LM** hashes.

Other servers accept all of these through the system's crypt and their own code.

## Decision
- **`Crypt-Password` also accepts `$y$` (yescrypt) and `$1$` (MD5-crypt).**
  - `Yescrypt` ports the reference implementation (Openwall, BSD-2-Clause; the copyright notice is kept in the file
    and in `THIRD-PARTY-LICENSES.md`).
  - It covers the standard pwxform flavour without a ROM, and classic scrypt, with the pre-hash libxcrypt applies to
    large settings.
  - Settings needing more than 1 GiB, hash upgrades (`g`) and ROMs are refused; such users are rejected.
  - A check with the common `$y$j9T$` uses 16 MiB and is cached on success, like bcrypt.
  - `Md5Crypt` is the classic 1000-round algorithm.
- **New check items**, in the names other servers use:
  - `MD5-Password` and `SMD5-Password`;
  - `SHA-Password` / `SHA1-Password` (unsalted SHA-1);
  - `SHA2-Password` (SHA-224 to SHA-512, told by the digest's length);
  - `SHA2-224/256/384/512-Password` (unsalted);
  - `LM-Password` (at most 14 ASCII characters, case-insensitive, as LM is).

  Values are hex or base64.
- **Still not supported**: argon2, which other servers' crypt does not offer either.
- These formats are weak (except yescrypt): they are for migrating existing databases. New passwords belong in
  yescrypt, bcrypt, SHA-crypt or PBKDF2.

## Tests
- `YescryptTest`:
  - classic scrypt and the yescrypt KDF against the reference's known answers;
  - nine `$y$` hashes of the reference with different N, r, p and flavours;
  - two hashes made by Debian's `mkpasswd -m yescrypt`, one of them the default `j9T` with the pre-hash;
  - malformed and unsupported settings.
- `PasswordCheckTest#legacyFormatsForMigration`:
  - MD5-crypt from `openssl passwd -1` and `mkpasswd`;
  - yescrypt through `Crypt-Password`;
  - MD5 (hex and base64), SHA-1, SHA-256 by length, salted MD5;
  - the LM hash of "password", case-insensitive, at most 14 characters.
