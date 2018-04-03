const util = require('util');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {buf_b32, b32_buf} = require('buf-b32');
const {getTOTP, verifyTOTP, toURI} = require('ztotp');
const mkdirp = require('zmkdirp');


// shorthand deviations: generates arrays [[0],[0,-1],[0,-1,-2],...]
const deviations = Array.from({length: 8}, ($,i) => Array.from({length: i+1, (_,d)=>-d));
// algs: none, sha1, sha256, sha512
const algs = [null, 'sha1', 'sha256', 'sha512'];


// shorthand password rounds: 2^n keys. Always make more than you'll need...
const rounds = Array.from({length: 64}, ($,n) => Math.pow(2, n));

// promisify crypto, fs functions: rng, pbkdf2, open, close, read, write, append, chmod
const [
	rng, pbkdf2,
	fopen, fclose,
	fread, fwrite, fappend,
	fchmod, ftrunc
] = [
	// crypto functions
	crypto.randomBytes, crypto.pbkdf2,
	// open and close routines
	fs.open, fs.close, 
	// read, write and append routines
	fs.read, fs.write, fs.appendFile,
	// read/write routines
	fs.chmod, fs.ftruncate
].map(util.promisify);

// environment variables

const {
	PASSELLFS = path.join(os.homedir(), '.passell'),
	DBN = 'default',
	PASSELLFSALLOC = '16 MiB',
	PASSELLFSTXT = path.join(PASSELLFS, `${DBN}.txt`),
	PASSELLFSBIN = path.join(PASSELLFS, `${DBN}.bin`),
	PASSELLFSPSW = path.join(PASSELLFS, `${DBN}.psw`),
	PASSELLFSPSK = path.join(PASSELLFS, `${DBN}.psk`),

	PASSELLPWMIN = '9',
	PASSELLPWRND = '18',

	PASSELLCKSRTLEN = '16',
	PASSELLCKSRT = ''
} = process.env

let [, n = '16', e = ''] = PASSELLFSALLOC
	.match(/(\d+(?:\.\d+)?)(?:\s*([KMGTP])?i?B)/)

const E = 'KMGTP'.indexOf(e.toUpperCase())

const SECRET = PASSELLCKSRT
	? Buffer.from(PASSELLCKSRT)
	: crypto.randomBytes(Math.max(16, Number.parseInt(PASSELLCKSRTLEN, 10) || 0))

const utils = {
	env: { // environment changed variables.
		dir: PASSELLFS,
		dbn: DBN,
		alloc: Number.parseInt(n, 10) * Math.pow(1024, E),
		pw_min: Number.parseInt(PASSELLPWMIN, 10) || 9,
		pw_rounds: Number.parseInt(PASSELLPWRND, 10) || 18,
		cookie_secret: SECRET
	},
	fn: { // constant functions
		buf_b32, b32_buf,
		getTOTP, verifyTOTP, toURI,
		rng, pbkdf2,
		mkdirp, fopen, fclose,
		fread, fwrite, fappend,
		fchmod, ftrunc,
	},
	constants: { // non-function constants
		deviations, rounds, algs
	}
};

module.exports = utils;

