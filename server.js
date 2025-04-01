import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();

const HOST = 'localhost';
const PORT = 5000;

app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('MongoDB is connected!');
    })
    .catch((error) => {
        console.error('Connection error:', error.message);
    });

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
});

const User = mongoose.model('User', userSchema);

const authenticate = (req, res, next) => {
    const token = req.header("Authorization")?.replace('Bearer', '').trim();
    
    if (!token) {
        res.status(401).json({ message: "No token provided!" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(500).json({ message: "Invalid or expired token!" });
    }
};

app.get('/', authenticate, async (req, res) => {
    try {
        const fetchAllUsers = await User.find();
        res.status(200).json({ fetchAllUsers });
    } catch (error) {
        res.status(500).json({ message: 'Error fetching users!' });
    }
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });

        if (existingUser) throw new Error('Email already exists!');

        const hashPassword = await bcrypt.hash(password, 10);
        const users = new User({ username, email, password: hashPassword });
        await users.save();

        res.status(200).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Registration failed!' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const users = await User.findOne({ email });
        if (!users) throw new Error('Email not found!');

        const isMatch = await bcrypt.compare(password, users.password);
        if (!isMatch) throw new Error('Email or password is incorrect!');

        const token = jwt.sign({ userId: users._id, email: users.email }, process.env.JWT_SECRET);
        res.status(200).json({ message: 'Login successful!', token });
    } catch (error) {
        res.status(500).json({ message: 'Email or password is incorrect!' });
    }
});

const adminUsername = "Admin";
const adminPassword = "123";

app.post('/adminlogin', (req, res) => {
    const { username, password } = req.body;
  
    if (username === adminUsername && password === adminPassword) {
  
      const token = jwt.sign({ username: adminUsername }, process.env.JWT_SECRET);
  
      res.json({ success: true, message: 'Login successful', token });
    } else {
      res.status(401).json({ success: false, message: 'Invalid username or password' });
    }
  });

app.listen(PORT, HOST, () => {
    console.log(`Server is running on port http://${HOST}:${PORT}`);
});