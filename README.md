# Pass&ell;

Combination password and OTP set. Uses many fields and has a global UID.

Presumes user names are between 2 and 20 characters, made of the character regex `/^[0-9A-Za-z_-]{2,20}$/`.


## Files

By default passell reads the following environment variables

```env
PASSELLFS="$HOME/.passell"
DBN="default"
PASSELLFSTXT="$PASSELLFS/$DBN.txt"
PASSELLFSBIN="$PASSELLFS/$DBN.bin"
PASSELLFSPSW="$PASSELLFS/$DBN.psw"
PASSELLFSPSK="$PASSELLFS/$DBN.psk"

PASSELLPWMIN=9
PASSELLPWRND=18
```

Passell reads from and writes to the files `$PASSELLFSTXT`, `$PASSELLFSBIN` and `$PASSELLFSPSW`. Passell only writes `$PASSELLPSK` once. Passell reads through the entirety of `$PASSELLFSTXT` once on start and emits `ready` when done.

New passwords have a minimum length of `$PASSELLPWMIN`, and are hashed through `pbkdf2` with a semi-random `salt` a total of `2^$PASSELLRND` times (eg default will hash 262144 times for a normal user, 8388608 times for user root).

Passwords are only checked before setting/at time of creation.

All previous files are `0o1600` by default (sticky, read-user, write-user). The parent dir is `0o1700` by default (sticky, u+rwx); allows multiple databases without knowing the exact name.

By default a username `root` (with uid 0) is available with a password generated at initalisation. This password is created randomly at initalisation and is 32 characters long with base32 encoding (see package [`buf-b32`](https://www.npmjs.com/package/buf-b32)). It is saved in `$HOME/.passell/$DBN.psk` with `0o1400` (sticky, u+r).

## Implementation details

### txt (uname) file

The username database is a newline separated array of names. It's stored in-memory and on-disk simultaneously. The user names (and screen names if enabled) are read, appended to and edited in-place. The screen name is disabled by default, but is stored in JSON delimited format (quoted) as opposed to plain text.


### Standard inital data

All binary database parts hold a minimum standard set of data `uid, uname, date`. `date` varies in what it holds; eg in `.bin` it holds sign-up date and in `.pwd` it holds last password change.


### bin (uinfo) file

* `uint32 uid [0,3]` covers approximately 4.2 billion users, a `root` user with uid `0`. Default is `uinfo.uid`.
* `str uname [4,24]` in ASCII. By default, presumes no spaces. Regular expression for users accessed from `passell.rgx.uname`. null (`0x00`) byte terminates string.
* `int48 signup [24,30]` contains the first time the user was created.
* `mask hasinfo [31,31]` holding:
	* `(mask & 128) hasLoggedIn` whether the user has ever been issued a login token. This is a flag that indicates that the user can be deleted if not set.
	* `(mask & 64) hasPhone` whether the user has set a phone number.
	* `(mask & 32) hasEmail` whether the user has set an email.
	* `(mask & 16) hasScreen` whether the user has set a preferred screen name. Note that this does not change the users uname or uid; and only acts as a reference.
	* `(mask & 7) sLen` log2 screen name length in bytes. Max is 127.
* `str email [32,111]` email primary (name) key in UTF-8.
* `str phone [112,127]` phone number in ASCII. Should have free bytes.
* `str screen[128,256]` screen name in UTF-8. Goes to `sLen` as a shortcut to get length.


### pwd (upass) file

* `uint32 uid [0,3]` covers approximately 4.2 billion users, a `root` user with uid `0`. Default is `uinfo.uid`.
* `str uname [4,24]` in ASCII. By default, presumes no spaces. Regular expression for users accessed from `passell.rgx.uname`. null (`0x00`) byte terminates string.
* `int48 pwchg [24,30]` contains the last password change in milliseconds.
* `uint8 pwrnd [31,31]` contains the amount of rounds (as a power of two) to use when generating a pwhash.
* `uint8 pwmin [32,32]` contains the minimum UTF-8 byte length of the password. Note that this is only verified by length and no other settings by default.
* `bytes salt [32, 47]` holds random bytes intended to increase the randomness of the hash. Renewed by `setPW` and `renewPW`.
* `mask totp0 [48, 48]` holding:
	* `(imask >>> 6) TOTPalg` of `[null, 'sha1', 'sha256', 'sha512']`, where `null` is disabled (TOTP is not available or otherwise disabled for this user). Values other than 0 and 1 (no tfa or tfa sha1) will not be usable by users of Googles' implementation. Default uninitialised is 0, default initialised is 1. Values 2 and 3 are only recommended for people using third party applications and should be under advanced selection.
	* `(imask & 63) TOTPTIn` is time interval. Default is 30 (0x1E) but can be set between 0 and 63 (min-max). Note that 0 will throw an error.
* `mask totp1 [49,49]` holding:
	* `(imask & 128) TOTPT0` is whether T0 differs. Reads T0 from first 5 bytes as int if true. Defaults to false (0x00)
	* `(imask >>> 4 & 7) TOTPtrials` is amount of trials, defaults to 4 (0x40).
	* `(imask & 15) TOTPlen` is TOTPValue mod 10^(len), or the length of the code. Defaults to 6 (0x06).
* `bytes TOTPSecret [50,80]` shared secret to use.
* `bytes hash [81,127]` pbkdf2 SHA384 hashsum to use.
* `uint8 otpr [128,128]` OTP hashsum rounds.
* `bytes otps [129,160]` OTP hashsum salt.
* `bytes otp [161,256]` 2 OTP hashes.

Used OTP hash will be zeroed on use. Only tested if `uinfo.pw_checkOTP` is called (should be on forget password page). _Must_ change main password after use. _Should_ offer a replacement one-time password. Hashes are only generated once and deleted after use. Passwords are generated from the sha1 hash of `otpr, otps, uname, Buffer.from(Date.now().toString(16).padStart(24,'0'),'hex')` and encoded as base32 for a 32 character case-insensitive one-time password. After this password is used it _must_ verify and reset (without notifying previous set user) password, email, phone and screen name (all users' info). The OTP is only given once. It must be given in one request and not stored further.


Internally, all integers (signed and unsigned) are stored as BE (`<Buffer 00 00 00 ff> === 255`) rather than LE (`<Buffer ff 00 00 00> === 255`) for primarily sorting reasons.


