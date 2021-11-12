const express = require('express')
const cookieSession = require('cookie-session')
const crypto = require('crypto');
const db = require('./database/database')

const app = express()

app.use('/public', express.static(__dirname + '/public'))
app.use(express.urlencoded({ extended: true }))
app.use(
	cookieSession
	({
		name: 'session',
		keys: ['key1', 'key2'],
	})
)

app.set('view engine', 'pug')
app.set('views', __dirname + '/views')

/** @type {import('express').RequestHandler} */
const ifNotLoggedin = (req, res, next) => 
{
	if (!req.session.LoggedIn) 
	{
		return res.redirect('login')
	}
	next();
}

/** @type {import('express').RequestHandler} */
const ifLoggedin = (req, res, next) => 
{
	if (req.session.LoggedIn)
	{
		return res.redirect('/type')
	}
	next()
}

const port = process.env.PORT ?? 80
app.listen(port, () => 
{
  console.log(`Ready! On port ${port}`)
})

/** Homepage */
app.get('/', (req, res) => 
{
  return res.render('home')
})

/** Login page */
app.get('/login', ifLoggedin , (req, res) => 
{
	return res.render('login')
})

/** Register page */
app.get('/register', ifLoggedin , (req, res) => 
{
	return res.render('register')
})

/** type */
app.get('/type', ifNotLoggedin , (req, res) => 
{
	return res.render('type', { username: req.session.username })
})

/** On user register */
app.post('/register', (req, res) => 
{
	if(req.body.password !== req.body['re-password']) 
	{
		return res.render('register', { error: 'Password is not match!' })
	} 
	else if (req.body.username === req.body.password) 
	{
		return res.render('register', { error: 'Do not set your password as your username!' })
	} 
	else if (req.body.password.length < 8)
	{
		return res.render('register', { error: 'Password is too short! Must be atleast 8 characters' })
	} 
	else if (req.body.username.length < 3) 
	{
		return res.render('register', { error: 'Username is too short!' })
	}
	else 
	{
		db.execute('SELECT * FROM users WHERE username = ?', [req.body.username])
		.then(([rows]) => { if ([rows].length > 1) { return res.render('register', { error: 'Username is already taken!' }) } })

		const hash = crypto.createHmac('sha256', req.body.password).digest('hex')
		db.execute('INSERT INTO `users` (username, password) VALUES (?, ?)', [req.body.username, hash])
		.then(async() => 
		{
			req.session.username = req.body.username
			req.session.id = await db.execute('SELECT id FROM users WHERE username = ?', [req.body.username]);
			req.session.LoggedIn = true
			res.redirect('/type')
		})
		.catch(err => {
			res.render('register', { error: `Something went wrong! Please try again` })
			console.error(err)
		})
	}
})

/** On user login */
app.post('/login', (req, res) => 
{
		const hash = crypto.createHmac('sha256', req.body.password).digest('hex')
		db.execute('SELECT * FROM `users` WHERE `username` = ?', [req.body.username])
		.then(async([rows]) => 
		{
			if (rows[0].length === 0) 
			{
				return res.render('login', { error: 'User is not found!' })
			}
			if (rows[0].password !== hash) 
			{
				return res.render('login', { error: 'Wrong password!' })
			}
			else 
			{
				req.session.username = req.body.username
				req.session.id = await db.execute('SELECT id FROM users WHERE username = ?', [req.body.username]);
				req.session.LoggedIn = true
				res.redirect('/type')
			}
		})
})