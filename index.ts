const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const joi = require('joi');
const app = express();
const port = 3000;

app.use(bodyParser.json());

import { Request, Response } from 'express';

interface UserDto {
  username: string;
  email: string;
  type: 'user' | 'admin';
  password: string;
}

interface UserEntry {
  email: string;
  type: 'user' | 'admin';
  salt: string;
  passwordhash: string;
}

// Database mock where the username is the primary key of a user.
const MEMORY_DB: Record<string, UserEntry> = {};

// CODE HERE
//
// I want to be able to register a new unique user (username and password). After the user is created I
// should be able to login with my username and password. If a user register request is invalid a 400 error
// should be returned, if the user is already registered a conflict error should be returned.
// On login the users crendentials should be verified.
// Because we dont have a database in this environment we store the users in memory. Fill the helper functions
// to query the memory db.

function getUserByUsername(name: string): UserEntry | undefined {
  // TODO
  return MEMORY_DB[name] ?? undefined;
}

function getUserByEmail(email: string): UserEntry | undefined {
  // TODO
  let user: UserEntry | undefined = undefined;
  Object.entries(MEMORY_DB).find(([username, userEntry]) => {
    if (userEntry?.email === email) {
      user = MEMORY_DB[username];
      return;
    }
  });

  return user;
}

// Request body -> UserDto
app.post('/register', (req: Request, res: Response) => {
  // Validate user object using joi
  // - username (required, min 3, max 24 characters)
  // - email (required, valid email address)
  // - type (required, select dropdown with either 'user' or 'admin')
  // - password (required, min 5, max 24 characters, upper and lower case, at least one special character)
  const SALT_ROUNDS = 10;
  const { username, email, type, password } = req.body;

  const userDto: UserDto = {
    username,
    email,
    type,
    password,
  };

  try {
    const schema = joi.object().keys({
      username: joi.string().required().min(3).max(24),
      email: joi.string().required().email(),
      type: joi
        .string()
        .required()
        .pattern(/user|admin/),
      password: joi
        .string()
        .required()
        .min(5)
        .max(24)
        .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*[-+_!@#$%^&*.,?]).+$/),
    });

    const result = schema.validate(userDto);
    const error = result?.error;
    if (error) {
      return res
        .status(400)
        .json({ message: `Invalid request data: ${error}` });
    }

    if (getUserByEmail(userDto.email)) {
      return res.status(400).json({ message: 'Email is already registered' });
    }

    if (getUserByUsername(userDto.username)) {
      return res
        .status(400)
        .json({ message: 'Username is already registered' });
    }

    const salt = bcrypt.genSaltSync(SALT_ROUNDS);
    const hash = bcrypt.hashSync(userDto.password, salt);

    MEMORY_DB[userDto.username] = {
      email: userDto.email,
      type: userDto.type,
      salt: salt,
      passwordhash: hash,
    };
    return res.json({
      message: 'User created successfully',
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

// Request body -> { username: string, password: string }
app.post('/login', (req: Request, res: Response) => {
  // Return 200 if username and password match
  // Return 401 else
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(422).json({ message: 'Must provide email and password' });
  }

  const userEntry = getUserByUsername(username);
  if (!userEntry) {
    return res.status(422).json({ message: 'Invalid password or email' });
  }

  try {
    const isValid = bcrypt.compareSync(password, userEntry.passwordhash);
    if (isValid) {
      return res.send('Login success!');
    }
  } catch (err) {
    return res.status(500).json({ message: `Something went wrong: ${err}` });
  }

  return res.status(401).json({ message: 'Invalid password or email' });
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
