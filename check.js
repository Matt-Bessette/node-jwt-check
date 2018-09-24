const KJUR = require('jsrsasign');
const express = require('express');
const morgan = require('morgan');
const env = require('node-env-file');

env('./.env');

const { JWT_SECRET, JWT_ISSUER, PORT } = process.env;
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

app.use(morgan(
	':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status ":referrer" ":user-agent" Authorization: ":req[authorization]"', 
	{skip: (req, res) => res.statusCode < 400 })
);

app.use((request, response) => {

	let token_header = request.get('Authorization');

	let token_pieces = [];

	if (token_header !== undefined){
		token_pieces = token_header.split(' ');
	}

	let token = '';

	if (Array.isArray(token_pieces) && token_pieces[0] === 'Bearer' && typeof token_pieces[1] === "string" ) {
		token = token_pieces[1];
	}

	let is_valid = false;

	if (token === '') {
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