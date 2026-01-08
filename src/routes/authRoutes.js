const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = mongoose.model('User');

const router = express.Router();

router.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = new User({ email, password });
    await user.save();

    const token = jwt.sign({ userId: user._id }, 'MY_SECRET_KEY');
    res.cookie('session_token', token, {
        maxAge: 900000, // Cookie expiration time (e.g., 15 minutes)
        httpOnly: true, // Prevents client-side JavaScript from reading the cookie (security enhancement)
        secure: true, // Must be true for cross-site (SameSite=None) in production (requires HTTPS)
        sameSite: 'None', // Required for cross-site requests. Use 'Lax' or 'Strict' if on the same domain
    });
    res.send({user});
  } catch (err) {
    return res.status(422).send(err.message);
  }
});

router.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).send({ error: 'Must provide email and password' });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(422).send({ error: 'Invalid password or email'});
  }

  try {
    await user.comparePassword(password);
    const token = jwt.sign({ userId: user._id }, 'MY_SECRET_KEY');
    res.cookie('session_token', token, {
        maxAge: 900000, // Cookie expiration time (e.g., 15 minutes)
        httpOnly: true, // Prevents client-side JavaScript from reading the cookie (security enhancement)
        secure: true, // Must be true for cross-site (SameSite=None) in production (requires HTTPS)
        sameSite: 'None', // Required for cross-site requests. Use 'Lax' or 'Strict' if on the same domain
    });
    res.send({user});
  } catch (err) {
    return res.status(422).send({ error: 'Invalid password or email' });
  }
});

module.exports = router;
