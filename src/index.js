const fs = require('fs');
const md5 = require('md5');
const sha1 = require('sha1');
const uuid = require('uuid/v1');
const bcrypt = require('bcrypt');
const express = require('express');
const smbhash = require('smbhash');
const mysql = require('async-mysql');
const templates = require('handlebars');
const bodyparser = require('body-parser');
const sessions = require('express-session');

// -----------

const db_host = process.env.DB_HOST || 'localhost';
const db_name = process.env.DB_NAME || 'test';
const db_user = process.env.DB_USER || 'root';
const db_pass = process.env.DB_PASS || 'root';
const u_table = process.env.U_TABLE || 'user';
const user_co = process.env.USER_CO || 'user';
const pass_co = process.env.PASS_CO || 'pass';
const passenc = process.env.PASSENC || 'none';
const scopeco = process.env.SCOPECO || user_co;

// -----------

const secure = function(txt)
{
	return txt.replace(/[^a-zA-Z0-9_\s\.\-\(\)\,\<\>\=\']+/g, '');
};

const verifyHash = async function(hash, password)
{
	if(passenc == 'bcrypt' && hash.indexOf('$2y$') == 0)
		return bcrypt.compare(password, '$2b$' + hash.substring(4));
	
	if(passenc == 'bcrypt')
		return bcrypt.compare(password, hash);
	
	if(passenc == 'sha1')
		return sha1(password) == hash.toLowerCase();
	
	if(passenc == 'md5')
		return md5(password) == hash.toLowerCase();
	
	if(passenc == 'nt')
		return smbhash.nthash(password) == hash.toUpperCase();
	
	return (hash === password);
};

// -----------

const db_config = { host: db_host, database: db_name, user: db_user, password: db_pass };
const sql = 'select ' + secure(pass_co) + ' AS _password_,' + secure(scopeco) + ' from ' + secure(u_table) + ' where ' + secure(user_co) + ' = ?';

const login = async function(user, pass, session)
{
	let db = await mysql.connect(db_config), data = await db.query(sql, [ user ]);
	let success = data && data.length > 0 && await verifyHash(data[0]['_password_'], pass);
	if(success) session.username = user;
	return success;
};

const isLoggedIn = function(session)
{
	if(session && session.username)
		return session.username;
	else return false;
};

const getLoggedInUserName = function(session)
{
	return session.username;
};

const getScope = async function(user, scope)
{
	let response = {}, db = await mysql.connect(db_config), data = await db.query(sql, [ user ]);
	if(data && data.length > 0)
		for(let col of scope.split(','))
		{
			col = col.trim();
			if(data[0][col]) response[col] = data[0][col];
		}
	return response;
};

// -----------

const client_requests = {};
client_requests.newId = uuid;

const genToken = function() // create a unique bearer token with a random character
{
	let token = uuid(), letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
	for(let i = 0; i < token.length; ++i)
		if(letters.indexOf(token.charAt(i)) < 0)
			token = token.substring(0, i) + letters.charAt(Math.floor(Math.random() * letters.length)) + (i < token.length - 1 ? token.substring(i + 1) : '');
	return token;
};

// -----------

const server = express();
server.use(sessions({ secret: 'oauth' }));
server.use(bodyparser.urlencoded({ extended: true }));

const template = function(res, file, data)
{
	let template = fs.readFileSync(file, 'utf8');
	let rendered = templates.compile(template)(data);
	res.send(rendered);
};

// -----------

server.route('/auth').get(function(req, res) // process client authentication request
{
	let request = { requested_at: new Date().getTime() };
	for(let param of [ 'response_type', 'redirect_uri', 'client_id', 'scope', 'state' ])
		if(req.query[param])
			request[param] = req.query[param];
	
	let id = client_requests.newId();
	client_requests[id] = request;
	
	let authenticated = isLoggedIn(req.session);
	res.redirect(authenticated ? ('/auth/' + id + '/react') : '/auth/' + id + '/login');
});

server.route('/auth/:id/login').get(function(req, res) // show login form
{
	let id = req.params.id, request = client_requests[id];
	template(res, 'template_login.html', { id: id, request: request });
});

server.route('/auth/:id/login').post(async function(req, res) // process login data
{
	try
	{
		let success = await login(req.body.user, req.body.pass, req.session);
		res.redirect(success ? ('/auth/' + req.params.id + '/react') : '/auth/' + req.params.id + '/login?error');
	}
	catch(x)
	{
		console.error(x);
		res.redirect('/auth/' + req.params.id + '/login?error');
	}
});

server.route('/auth/:id/react').get(function(req, res) // show "allow/deny" form
{
	let id = req.params.id, request = client_requests[id];
	template(res, 'template_react.html', { id: id, request: request });
});

server.route('/auth/:id/react').post(function(req, res) // process "allow/deny" data
{
	let id = req.params.id, request = client_requests[id], success = request.allow = (req.body.allow == 'yes');
	if(success)
	{
		request.user = getLoggedInUserName(req.session);
		res.redirect(request.redirect_uri + (request.redirect_uri.indexOf('?') > -1 ? '&' : '?') + 'code=' + id + '&state=' + request.state);
	}
	else
	{
		res.status(302);
		res.redirect(request.redirect_uri + (request.redirect_uri.indexOf('?') > -1 ? '&' : '?') + 'error=access_denied&state=' + request.state);
	}
});

server.route('/token').post(function(req, res) // token exchange
{
	let code = req.body.code, request = client_requests[code];
	
	if(req.body.grant_type == 'authorization_code' && request.allow && req.body.client_id == request.client_id)
		res.send({ token_type: 'bearer', access_token: request.bearer = genToken(), scope: request.scope });
	
	else res.status(500).send({ error: 'access_denied' });
});

server.route('/api').get(async function(req, res) // give access to scope
{
	try
	{
		let token = req.headers.authorization && req.headers.authorization.substring(7);
		let request = Object.values(client_requests).find(function(request) { return request.bearer === token });
		
		if(typeof request !== 'undefined')
			res.send(await getScope(request.user, request.scope));
		
		else res.status(403).send({ error: 'invalid access token' });
	}
	catch(x)
	{
		res.status(500);
		console.error(x);
		res.send({ error: 'exception' });
	}
});

server.listen(80, function() // start server
{
	console.log('oauth server started');
});