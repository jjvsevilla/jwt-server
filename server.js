import express from 'express';
import faker from 'faker';

// middlewares
import cors from 'cors';
import bodyParser from 'body-parser';
import morgan from 'morgan';

import jwt from 'jsonwebtoken';
import expressJwt from 'express-jwt';
import jwtDecode from 'jwt-decode';

const JWT_SECRET = 'Gl0b4nt123$';
const HOST = 'localhost';
const PORT = 3001;

const dataBase = {
  users: [
    {
      userId: '165a3bf6-9b9b-11e8-98d0-529269fb1459',
      username: 'globant',
      password: '123',
      organization: 'Globant',
      site: 'Lima',
      topic: 'JWT Talk',
      firstname: 'Juan',
      lastname: 'Vento'
    },
    {
      userId: '165a3e8a-9b9b-11e8-98d0-529269fb1459',
      username: 'react',
      password: '123',
      organization: 'Globant',
      site: 'Lima',
      topic: 'JWT Talk',
      firstname: 'Reactito',
      lastname: 'Js'
    },
    {
      userId: '165a3fd4-9b9b-11e8-98d0-529269fb1459',
      username: 'angular',
      password: '123',
      organization: 'Globant',
      site: 'Lima',
      topic: 'JWT Talk',
      firstname: 'Angularcito',
      lastname: 'Js'
    }
  ]
}

const publicUrls = [
  '/login',
  '/open-resource'
]

const app = express();

// morgan is our request logger middleware
app.use(morgan('tiny'));

// enable CORS in our express server
app.use(cors());

// bodyParser parse incoming request´s body
app.use(bodyParser.json());

// expressJwt validate that the HTTP request has the JWT token
app.use(expressJwt({ secret: JWT_SECRET })
  .unless({ path: [ ...publicUrls ]}));

// unauthorized error handler function
app.use(function (err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    res.status(401).send({ message: err.message });
  }
});

app.post('/login', (req, res) => {
  const { body } = req;

  if (!body.username || !body.password) {
    res
      .status(400)
      .send({ message: 'You need a username and password.' });
    return;
  }

  const user = dataBase.users.find(user =>
      user.username === body.username && user.password === body.password);

  if (!user) {
    res
      .status(401)
      .send({ message: 'User not found. Your credentials might be wrong.' });
    return;
  }

  const { userId, username, organization, site } = user;

  // jwt.sign(payload, secretOrPrivateKey, [options, callback])
  // default algorithm (HMAC SHA256)
  // returns the JsonWebToken as string
  const token = jwt.sign({
    username,
    organization,
    site
  }, JWT_SECRET, {
    issuer: 'jwt-server',
    subject: 'auth-token',
    audience: userId,
    expiresIn: '60s',
    algorithm: 'HS256' // default
  });

  res
    .status(200)
    .send({
      access_token: token,
      user
    });
});

app.get('/random-user', (req, res) => {
  const user = faker.helpers.userCard();
  user.avatar = faker.image.avatar();
  res
    .status(200)
    .send({
      randomUser: user
    });
});

app.get('/me', (req, res) => {
  const token = req.headers.authorization;
  const decoded = jwtDecode(token);
  const user = dataBase.users.find(user => user.userId === decoded.aud);

  if (!user) {
    res
      .status(401)
      .send({ message: 'User not found.' });
    return;
  }

  res
    .status(200)
    .send({
      user
    });
});

app.get('*', (req, res) => {
  res.status(404).send({ message: 'The requested resource could not be found' });
});

app.listen(PORT, HOST, () => {
  console.log(`Auth server listening on ${HOST}:${PORT}`);
});
