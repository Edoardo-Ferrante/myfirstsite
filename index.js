const express = require('express');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const session = require('express-session');
app.use(session({
  secret: 'jhefushfs8y7t7632yihiuwhyfeswfvsyegf',
  resave: false,
  saveUninitialized: true
}));
app.use(express.static('public'));

// Use express middleware to parse form data
app.use(express.urlencoded({ extended: false }));

const db = new sqlite3.Database('users.db');
db.run('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)', err => {
  if (err) {
    console.error(err.message);
  } else {
    // Start the server
    app.listen(port, () => {
      console.log(`Server is listening on port ${port}`);
    });
  }
});

// Serve the / page
app.get('/', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.redirect('/home');
  } else {
    res.redirect('/login');
  }
});

// Serve the login page
app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

// Serve the registration page
app.get('/register', (req, res) => {
  res.sendFile(__dirname + '/register.html');
});

// Serve the home page
app.get('/home', (req, res) => {
  if (req.session && req.session.authenticated) {
    res.sendFile(__dirname + '/home.html')
  } else {
    res.redirect('/login');
  }
});

// Handle registration form submission
app.post('/register', (req, res) => {
  const db = new sqlite3.Database('users.db');
  const username = req.body.username;
  const password = req.body.password;

  // Hash the password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error(err.message);
      res.sendStatus(500);
      return db.close();
    }

    // Insert the new user into the database
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', username, hash, err => {
      if (err) {
        console.error(err.message);
        res.sendStatus(500);
      } else {
        // Redirect the user to the home page
        res.redirect('/home');
      }
      db.close();
    });
  });
});
// Handle logout request
app.post('/logout', (req, res) => {
  res.redirect('/login');
});

// Handle login form submission
app.post('/login', (req, res) => {
  const db = new sqlite3.Database('users.db');
  const username = req.body.username;
  const password = req.body.password;

  // Check if the user exists
  db.get('SELECT * FROM users WHERE username = ?', username, (err, row) => {
    if (err) {
      console.error(err.message);
      res.sendStatus(500);
      return db.close();
    }

    if (!row) {
      res.send('Invalid username or password');
      return db.close();
    }

    // Compare the password hash
    bcrypt.compare(password, row.password, (err, isMatch) => {
      if (err) {
        console.error(err.message);
        res.sendStatus(500);
        return db.close();
      }
      if (isMatch) {
        req.session.authenticated = true; // set the authenticated flag in the session
        res.redirect('/home');
      } else {
        res.send('Invalid username or password');
      }
      // close the database connection
      db.close();
    });
  });
});