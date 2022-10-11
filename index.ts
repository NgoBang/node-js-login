const express = require('express');
const bcrypt = require('bcryptjs');
const joi = require('joi');
const app = express();
const port = 3000;

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
  Object.entries(MEMORY_DB).find(([key, userEntry]) => {
    if (userEntry?.email === email) {
      return MEMORY_DB[key];
    }
  });

  return undefined;
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
      type: joi.string().required(),
      password: joi
        .string()
        .regex('^(?=.*[a-z])(?=.*[A-Z])(?=.*[-+_!@#$%^&*.,?]).+$')
        .min(3)
        .max(24)
        .required(),
    });

    joi.validate(userDto, schema, (err: any, value: any) => {
      console.log('value', value);
      if (err) {
        return res.status(400).send({
          message: 'Invalid request data',
        });
      }

      if (getUserByUsername(userDto.email)) {
        return res.status(400).send({
          message: 'Username is already registered',
        });
      }

      const salt = bcrypt.genSaltSync(SALT_ROUNDS);
      const hash = bcrypt.hashSync(password, salt);

      const userEntry: UserEntry = {
        email: userDto.email,
        type: userDto.type === 'user' ? 'user' : userDto.type,
        salt: salt,
        passwordhash: hash,
      };

      MEMORY_DB[userDto.username] = userEntry;

      return res.status(200).send({
        message: 'User created successfully',
      });
    });
  } catch (err) {
    return res.status(422).send({ message: err.message });
  }
});

// Request body -> { username: string, password: string }
app.post('/login', (req: Request, res: Response) => {
  // Return 200 if username and password match
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(422).send({ message: 'Must provide email and password' });
  }

  const userEntry = getUserByEmail(email);
  if (!userEntry) {
    return res.status(422).send({ message: 'Invalid password or email' });
  }

  try {
    const isValid = bcrypt.compareSync(password, userEntry.passwordhash);
    if (isValid) {
      return res.status(200).send({
        message: 'Login success!',
      });
    }
  } catch (err) {
    return res.status(401).send({
      message: 'Invalid password or email',
    });
  }

  return res.status(401).send({
    message: 'Invalid password or email',
  });
  // Return 401 else
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
