const crypto = require('crypto');
const {cookie_secret} = require('./env');

// generic functions
const fnull = () => null
const clearFalsy = v => v
const vToString = v => v.toString()
const akvo = (o = Object.create(null), [k, v = '']) => {
	if (k in v) o[k].push(v)
	else o[k] = [v]
	return o;
};
// array key value objectify

// regex murders
const ne = /\=+$/
const cASCII = /^[\!\.0-9A-Za-z_-]*$/
const cspl = /[\=\.]/g

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

// constant cookie signing things
const digest = 'base64',
	algo = 'sha256',
	b64len = 43,
	zero = 0,
	setCookie = 'set-cookie';

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


const cookie_attrs = (a='',c) => {
	switch (typeof c) {
		case 'string':
			return `${a}; ${c}`
		case 'object':
			if (Array.isArray(c))
				return `${a}; ${c.join('=')}`
		default: return a
	}
};
// cookie attributes

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
		if (!f && !this.flags) return ''
		if (Array.isArray(f)) return this._flags = f.reduce(
			cookie_attrs,
			this._flags
		);
		if ('string' === typeof f)
			return this._flags = `${this.flags || ''}; ${f}`
		;
	},
	toString() {
		if (!this.signed) return `${this.name}=...`;
		return `${this.name}={b64_e(this.value)}.${
			'string' === typeof this.signed
				? this.signed
				: this.resign()
		}${this.flags || ''}`;
	},
	make(name, value, signed, flags = '') {
		const c = Object.create(scookie);
		c._name = name;
		c._value = value;
		c._signed = signed;
		c.flags = flags;
		return c;
	}
};


// keys
const __CSRF = '__Host-csrf',
	UINFO = '__Host-uinfo';


const ccookies = {
	__CSRF,
	UINFO,
	cookie_secret,
	scookie,
	sign(name, val, ...attrs) {
		if (!(String(name) === name || name.match(cASCII))) throw new RangeError(
			`Characters used in the cookie named ${name} is not within the ${cASCII.toString()} range.`
		);

		return scookie.make(name, val, true, attrs);
	},
	unsign(c) {
		const [name, str, b64, sign] = c
			.split(cspl);
		const safe = sign.length !== b64len ? false
			: crypto.timingSafeEqual(
				Buffer.from(sign, 'base64'),
				hmkc(name, val).digest()
			);
		const val = safe ? b64_d(null, str, b64) : '';
		return scookie.make(name, val, safe ? sign : false);
	},
	unsignAll(ck) {
		const cookies = ck.headers && ck.headers.cookie
			? ck.headers.cookie
			: (ck.cookie || ck);
		switch (typeof cookies) {
			case 'undefined': 
				return Object.create(null);
			case 'string': return cookies
				.split('; ')
				.map(cryp.unsignCookie)
				.reduce(akvo, Object.create(null));
			case 'object':
				if (Array.isArray(cookies)) 
					return cookies.reduce(akvo, Object.create(null));
			default: return Object.create(null);
		}
	},

	_csrf() {
		const d = Date.now()+csrfExpires
		return ccookies.sign(
			__CSRF,
			d.toString(16).padStart(16,'0'),
			String.raw`Expires=${UTC(d)}; Secure; Path=/`
		);
	},
	_ccsrf(csrf) {
		const _ = csrf.headers && csrf.headers.cookie
			? ccookies.unsignAll(csrf)[__CSRF]
			: (csrf[__CSRF] || csrf);
		if (!_) return ccookies._csrf();
		if (_.signed) {
			const expires = Number.parseInt(_, 16);
			if (expires > (Date.now()-csrfRenew))
				return ccookies._csrf();
			
			return null;
		} else {
			const err = new Error('Bad CSRF token');
			err.code = 'EBADCSRF';
			throw err;
		}
	},

	__setCookie(name, value, ...attr) {
		if (!name) return this.cookies
		switch (typeof name) {
			case 'string': if ('undefined' !== typeof value)
				return this.cookies.set(
					name,
					scookie.make(
						name,
						value,
						true,
						attr.reduce(cookie_attr, '')
					)
				)
			case 'object':
				return this.cookies.set(
					name.name,
					name
				);
			default: return this.cookies
		}
	},
	__setCookieHead() {
		const cookies = Array.from(
			this.cookies.values(),
			vToString
		).filter(clearFalsy);
		this.setHeader(setCookie, cookies);
		return cookies
	},
	middleware(req, res, next = fnull) {
		const cookies = ccookies.unsignAll(req)
		req.cookies = cookies
		res.cookies = new Map
		res.setCookie = ccookies.__setCookie.bind(res)
		res.setCookieHead = ccookies.__setCookieHead.bind(res)

		if (cookies[__CSRF])
			res.setCookie(ccookies._ccsrf(cookies))
		;;
		return next()
	}
};

module.exports = ccookies;

