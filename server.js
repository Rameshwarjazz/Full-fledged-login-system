const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

const app = express();
const port = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/login-system', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Define User model
const User = mongoose.model('User', {
  username: String,
  password: String,
});

// Configure middleware
app.use(express.static('public'));
app.use(express.json()); // Parse JSON request bodies
app.use(
  session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
      mongoUrl: 'mongodb://127.0.0.1:27017/login-system',
    }),
  })
);

// Define routes

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.post(
  '/register',
  [
    body('username')
      .isLength({ min: 1 })
      .trim()
      .withMessage('Username is required'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long'),
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { username, password } = req.body;

      const existingUser = await User.findOne({ username });
      if (existingUser) {
        console.log('User already exists:', existingUser.username);
        return res
          .status(400)
          .json({ message: 'Username already in use. Please choose another one.' });
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a new user
      const user = new User({
        username,
        password: hashedPassword,
      });

      await user.save();

      res.status(200).json({ message: 'Registration successful! Please log in.' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Registration failed. Please try again later.' });
    }
  }
);

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find user by username
    const user = await User.findOne({ username });

    if (user) {
      // Check the password
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (passwordMatch) {
        req.session.userId = user._id;
        return res.status(200).json({ message: 'Login successful!' });
      }
    }

    res.status(401).json({ message: 'Invalid username or password' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Login failed. Please try again later.' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.status(200).json({ message: 'Logout successful!' });
  });
});

app.get('/dashboard', (req, res) => {
  if (req.session.userId) {
    res.status(200).json({ message: 'Welcome to the dashboard!' });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
