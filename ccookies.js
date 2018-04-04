const crypto = require('crypto');
const {cookie_secret} = require('./env');

// times
const csrfExpires = 8*24*36e5
// just over a week
const csrfRenew = (csrfExpires>>1)
// renew __Host-csrf after this amount of milliseconds

const aWeek = 7*24*3600;
const aWeekMS = aWeek*1e3;
// a week 
const aYear = 365.25*24*3600;
const aYearMS = aYear*1e3;
// a year

const UTC = d => new Date(d).toUTCString();

// cookie signing
const digest = 'base64',
	algo = 'sha256',
	b64len = 43,
	zero = 0;

const _hmkc = (h = crypto.createHmac(algo, SECRET), v) => h.update(
	String(v) + '\n'
);
const hmkc = (...k) => k.reduce(
	_hmkc,
	crypto.createHmac(algo, SECRET)
);
const hmkc64 = (...k) => hmkc(...k)
	.digest(digest)
	.slice(zero, b64len);
// of constant length.

const b64_e = (s = '') => String(s)
	.match(cASCII)
	? String.raw`.${str}`
	: Buffer.from(String(s), 'utf8')
		.toString('base64')
		.replace(ne,'') + '.'
// of unknown length

const b64_d = (k, str = k.split('.')[0], b64 = k.split('.')[1]) => str || Buffer.from(b64, 'base64').toString('utf8');


const cookie_attrs = (a,c) => {
	switch (typeof c) {
		case 'string':
			return `${a}; ${c}`
		case 'object':
			if (Array.isArray(c))
				return `${a}; ${c.join('=')}`
		default: return a
	}
}; // cookie attributes

// secure cookie
const scookie = {
	get name() {return this._name;},
	set name(n){
		if (String(n).match(cASCII))
			return this._name = String(n);
		else return false;
	},
	get value() {return this._value;},
	set value(v) {
		this._value = v;
	},
	get signed() {return this._signed;},
	resign() {
		// don't resign unless already signed
		if (this._signed) return this._signed = hmkc64(
			this.name,
			this.value
		);
		return false
	},
	get flags() {return this._flags;},
	set flags(f){
		if (Array.isArray(f)) return this._flags = f.reduce(
			cookie_attrs,
			this._flags
		);
		if ('string' === typeof f)
			return this._flags = `${this.flags}; ${f}`
		;
	},
	toString() {
		if (!this.signed) return '';
		return `${this.name}={b64_e(this.value)}.${
			'string' === typeof this.signed
				? this.signed
				: this.resign()
		}`;
	},
	make(name, value, signed, flags = '') {
		const c = Object.create(scookie);
		c._name = name;
		c._value = value;
		c._signed = signed;
		c._flags = Array.isArray(flags)
			? flags.reduce(cookie_attrs, '')
			: flags;
		return c;
	}
};


// keys
const __CSRF = '__Host-csrf',
	UINFO = '__Host-uinfo';
