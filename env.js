const fs = require('fs');
const {mkdirpSync} = require('zmkdirp');
// environment variables

const {
	// main top-level directory
	PASSELLFS = path.join(os.homedir(), '.passell'),
	// name of database. Please do change this.
	DBN = 'default',
	// Space to allocate for certain files
	PASSELLFSALLOC = '16 MiB',
	// username\0"User's screen name"\n file
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

	// secret. set via PASSELLSRT and it is a buffer from a string, set via PASSELLFSSRT and it is a buffer that won't change
	PASSELLCKSRT = fs.accessSync(PASSELLFSSRT, fs.constants.R_OK)
		? fs.readFileSync(PASSELLFSSRT)
		: null
} = process.env

// do making and chmodding
const dir = mkdirpSync(PASSELLFS)
fs.chmodSync(PASSELLFS, 0o1700)

// resolve settings
const [, n = '16', e = '', b = 'B'] = PASSELLFSALLOC
	.match(/(\d+(?:\.\d+)?)(?:\s*([KMGTP])?i?(B|b)?)/)

const E = 'KMGTP'.indexOf(e.toUpperCase());

// check if secret exists
const SECRET = PASSELLCKSRT
	// fill if it does
	? Buffer.isBuffer(PASSELLCKSRT) ? PASSELLCKSRT : Buffer.from(PASSELLCKSRT)
	// make if it doesn't
	: (()=>{
		try {
			return fs.readFileSync(PASSELLFSSRT);
		} catch (e) {
			const data = crypto.randomBytes(256);
			fs.writeFileSync(PASSELLFSSRT, data, {encoding: null, mode: 0o1600});
			fs.chmodSync(PASSELLFSSRT, 0o1400);
			return data;
		};
	})();

module.exports = {
	// environment set changed variables.
	dir,
	dbn: DBN,
	txt: PASSELLFSTXT,
	bin: PASSELLFSBIN,
	psw: PASSELLFSPSW,
	psk: PASSELLFSPSK,
	srt: PASSELLFSSRT,

	// file allocation default (bin, psw)
	alloc: (
		Number.parseInt(n, 10) * Math.pow(1024, E)
	) / (b === 'b' ? 8 : 1),
	
	// password minimums
	pw_min: Number.parseInt(PASSELLPWMIN, 10) || 9,
	pw_rounds: Number.parseInt(PASSELLPWRND, 10) || 18,

	// secret to sign cookies with.
	cookie_secret: SECRET
};

