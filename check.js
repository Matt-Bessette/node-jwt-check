const KJUR = require('jsrsasign');
const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const env = require('node-env-file');

env('./.env');

const { JWT_SECRET, JWT_ISSUER, PORT, COOKIE_NAME } = process.env;
const app = express();
const default_port = 9050;
let port = default_port;

if (JWT_SECRET == undefined || JWT_SECRET == '') {
	console.warn(`Invalid JWT_SECRET provided in environment file`);
}

if (JWT_ISSUER == undefined || JWT_ISSUER == '') {
	console.warn(`Invalid JWT_ISSUER provided in environment file`);
}

if (PORT != undefined) {
	port = PORT;
} else {
	console.warn(`Invalid PORT provided in environment file: ${PORT} defaulting to ${default_port}`);
}

if (COOKIE_NAME == undefined || COOKIE_NAME == '') {
	console.warn(`Invalid COOKIE_NAME provided in environment file`);
}

app.use(cookieParser());

app.use(morgan(
	':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status ":referrer" ":user-agent" Authorization: ":req[authorization]"', 
	{skip: (req, res) => res.statusCode < 400 })
);

app.use((request, response) => {

	let token = request.cookies[COOKIE_NAME];

	if (token === '' || token === undefined) {
		return response.status(403).send();
	}

	try {
		is_valid = KJUR.jws.JWS.verifyJWT(token, JWT_SECRET, {
			alg: ['HS256'],
			typ: ['JWT'],
			iss: JWT_ISSUER
		});
	} catch(e) {
		console.warn(e);
	}

	if (is_valid) {
		return response.status(200).send();
	}
	
	return response.status(403).send();
});

app.listen(port, () => {
	console.log(`JWT auth server listening on port ${port}`);
});