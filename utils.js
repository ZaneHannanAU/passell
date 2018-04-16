const util = require('util');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {buf_b32, b32_buf} = require('buf-b32');
const {getTOTP, verifyTOTP, toURI} = require('ztotp');
const mkdirp = require('zmkdirp');


// shorthand deviations: generates arrays [[0],[0,-1],[0,-1,-2],...]
const totp_deviations = Array.from({length: 8}, ($,i) => Array.from({length: i+1}, (_,d)=>-d));
// algs: none, sha1, sha256, sha512
const totp_algs = [null, 'sha1', 'sha256', 'sha512'];


// shorthand password rounds: 2^n keys. Always make more than you'll need...
const pw_rounds = Array.from({length: 64}, ($,n) => Math.pow(2, n));

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

const freeBlock = (()=>{
	const free = Buffer.allocUnsafe(pw_rounds[16])
	const bins = Array.from({length: 128},(_,i)=>free.slice(i*512,(i+1)*512))
	return {
		bins,
		get(){return bins.shift() || Buffer.allocUnsafe(512)},
		give(b){bins.push(b)}
	}
})()

const utils = {
	env: require('./env'),
	cookies: require('./ccookies'),
	fn: { // constant functions
		// base32
		buf_b32, b32_buf,
		// 512 byte blocks
		freeBlock,
		// totp/otp
		getTOTP, verifyTOTP, toURI,
		// crypto
		rng, rnf, pbkdf2,
		// files and folders
		mkdirp, fopen, fclose,
		// data modify
		fread, fwrite, fappend,
		// data cut and perms
		fchmod, chmod, ftrunc,
	},
	constants: { // non-function constants
		// totp
		totp_deviations,
		totp_algs,
		// password
		pw_rounds,
		pw_alg: 'sha384',
		// otp
		otp_rounds: pw_rounds+5,
		otp_alg: 'sha384',
		// email reset
		ereset_alg: 'sha512'
	}
};

module.exports = utils;

