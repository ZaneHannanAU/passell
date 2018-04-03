const util = require('util');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {buf_b32, b32_buf} = require('buf-b32');
const {getTOTP, verifyTOTP, toURI} = require('ztotp');
const mkdirp = require('zmkdirp');


// shorthand deviations: generates arrays [[0],[0,-1],[0,-1,-2],...]
const deviations = Array.from({length: 8}, ($,i) => Array.from({length: i+1}, (_,d)=>-d));
// algs: none, sha1, sha256, sha512
const algs = [null, 'sha1', 'sha256', 'sha512'];


// shorthand password rounds: 2^n keys. Always make more than you'll need...
const rounds = Array.from({length: 64}, ($,n) => Math.pow(2, n));

// promisify crypto, fs functions: rng, pbkdf2, open, close, read, write, append, chmod
const [
	rng, rnf, pbkdf2,
	fopen, fclose,
	fread, fwrite, fappend,
	fchmod, chmod, ftrunc
] = [
	// crypto functions
	crypto.randomBytes, crypto.randomFill, crypto.pbkdf2,
	// open and close routines
	fs.open, fs.close,
	// read, write and append routines
	fs.read, fs.write, fs.appendFile,
	// modifications
	fs.fchmod, fs.chmod, fs.ftruncate
].map(util.promisify);

// environment variables

const {
	// main top-level directory
	PASSELLFS = path.join(os.homedir(), '.passell'),
	// name of database. Please do change this.
	DBN = 'default',
	// Space to allocate for certain files
	PASSELLFSALLOC = '16 MiB',
	// username\0"User's screen name" file
	PASSELLFSTXT = path.join(PASSELLFS, `${DBN}.txt`),
	// Information holder
	PASSELLFSBIN = path.join(PASSELLFS, `${DBN}.bin`),
	// Password file
	PASSELLFSPSW = path.join(PASSELLFS, `${DBN}.psw`),
	// root password (uid 0)
	PASSELLFSPSK = path.join(PASSELLFS, `${DBN}.psk`),
	// cookie secret. only villains change this.
	PASSELLFSSRT = path.join(PASSELLFS, `${DBN}.srt`),

	// password minimum length
	PASSELLPWMIN = '9',
	// 2^n password rounds
	PASSELLPWRND = '18',

	// secret. set via PASSELLSRT and it is a buffer, set via PASSELLFSSRT and it is a buffer that won't change
	PASSELLCKSRT = fs.accessSync() ? fs.readFileSync(PASSELLFSSRT) : ''
} = process.env

let [, n = '16', e = ''] = PASSELLFSALLOC
	.match(/(\d+(?:\.\d+)?)(?:\s*([KMGTP])?i?B)/)

const E = 'KMGTP'.indexOf(e.toUpperCase())

// check if secret exists
const SECRET = PASSELLCKSRT
	// fill if it does
	? Buffer.isBuffer(PASSELLCKSRT) ? PASSELLCKSRT : Buffer.from(PASSELLCKSRT)
	// make if it doesn't
	: (()=>{
		const data = crypto.randomBytes(256);
		fs.writeFileSync(data, {encoding: null, mode: 0o1400})
		return data
	})()

const utils = {
	env: { // environment set changed variables.
		dir: PASSELLFS,
		dbn: DBN,
		alloc: Number.parseInt(n, 10) * Math.pow(1024, E),
		pw_min: Number.parseInt(PASSELLPWMIN, 10) || 9,
		pw_rounds: Number.parseInt(PASSELLPWRND, 10) || 18,
		cookie_secret: SECRET
	},
	fn: { // constant functions
		// base32
		buf_b32, b32_buf,
		// totp/otp
		getTOTP, verifyTOTP, toURI,
		// crypto
		rng, rnf, pbkdf2,
		// files and folders
		mkdirp, fopen, fclose,
		// data modify
		fread, fwrite, fappend,
		// data understand
		fchmod, chmod, ftrunc,
	},
	constants: { // non-function constants
		// totp
		deviations, algs,
		// password
		rounds, alg: 'sha384'
	}
};

module.exports = utils;

