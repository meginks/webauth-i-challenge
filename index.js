const express = require('express'); 
const helmet = require('helmet'); 
const cors = require('cors'); 
const bcrypt = require('bcryptjs'); 
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')('session'); 

const db = require('./data/dbConfig.js');
const Users = require('./users/users-router.js');

const server = express(); 

const sessionConfig = {
  name: 'webauth-i-challenge', 
  secret: process.env.SECRET || 'secret', 
  cookie: {
    maxAge: 1000 * 60 * 60, 
    secure: false,
    httpOnly: true
  }, 
  resave: false,
  saveUninitialized: false,
  store: new KnexSessionStore({
    knex: db, 
    tablename: 'sessions',
    sidfieldname: 'sid',
    createtable: true,
    clearInterval: 1000*60*10
  })
}

const restricted = require('./restricted-middleware.js'); 


server.use(helmet()); 
server.use(express.json());
server.use(cors('headers')); 
server.use(session(sessionConfig));

/// Registration Endpoint 

server.post('/api/register', (req, res) => {
    let user = req.body;
    const hash = bcrypt.hashSync(user.password, 4)
    user.password = hash
  
    Users.add(user)
      .then(saved => {
        res.status(201).json(saved);
      })
      .catch(error => {
        res.status(500).json({error, message: 'You shall not pass!'});
      });
  });

// Login Endpoint 

server.post('/api/login', (req, res) => {
    let { username, password } = req.body;
  
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          req.session.user = user
          res.status(200).json({ message: `Welcome ${user.username}!` });
        } else {
          res.status(401).json({ message: 'Invalid Credentials. You shall not pass!' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });

  // Logout Endpoint 

  server.get('/api/logout', (req, res) => {
    if (req.session) {
      req.session.destroy(error => {
        if (error) {
          res.status.json({message: 'You are trapped here. Sorry.'})
        } else {
          res.send('Bye bye for now!')
        }
      })
    } else {
      res.status(401).json({message: `please make sure your session is working`})
    }
  })


  /// GET ALL USERS ENDPOINT 

  server.get('/api/users', restricted, role('admin'), (req, res) => {
    Users.find()
      .then(users => {
        res.json(users);
      })
      .catch(err => res.send(err));
  });
  
  
  function role(title) {
    return function(req, res, next) {
      if(req.headers.title === title) {
        next()
      } else {
        res.status(403).json({message: 'You shall not pass!'})
      }
    }
  }
  
  
  function restricted(req, res, next) {
    const {username, password} = req.headers;
  
    if(username && password) {
      Users.findBy({username})
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next()
        } else {
          res.status(401).json({message: 'Invalid Credentials. You shall not pass!'})
        }
      }).catch(error => {
        res.status(500).json({message: 'Something went wrong on our end. You shall not pass!',
      error: error})
      })
    } else {
      res.status(400).json({message: 'No credentials provided. You shall not pass!'})
    } 
  }
  


const port = process.env.PORT || 5000; 

server.listen(port, () => {
    console.log(`\n** running on port ${port} **\n`); 
})