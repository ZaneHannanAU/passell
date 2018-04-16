const {
	constants: {
		totp_deviations, totp_algs,
		pw_rounds, pw_alg,
		otp_rounds, otp_alg,
		ereset_alg,
	},
	fn: {
		buf_b32, b32_buf,
		freeBlock,
		getTOTP, verifyTOTP, toURI,
		rnf, pbkdf2,
		fread, fwrite
	}
} = require('./utils')

class PW {
	static async open(uid) {
	constructor(buf) {
