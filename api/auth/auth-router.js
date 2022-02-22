const router = require('express').Router();
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model')
const {checkPasswordLength, checkUsernameExists, checkUsernameFree} = require('./auth-middleware')
// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!

router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 12);
    Users.add({ username, password: hash})
    .then(user => {
      res.status(201).json(user)
    })
    .catch(next)
})

router.post('/login', checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if(bcrypt.compareSync(password, req.user.password)) {
    req.session.user = req.user;
    res.status(200).json({ message: `Welcome ${req.user.username}`})
  } else {
    next({ status: 401, message: 'Invalid credentials' })
  }
})


router.get('/logout', (req, res, next) => {
  if(req.session.user) {
    req.session.destroy(err => {
      if (err) {
        next(err)
      } else {
        res.status(200).json('logged out')
      }
    })
      } else {
        next({ status: 200, message: 'no session' })
      }
})


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router