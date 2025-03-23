import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';

dotenv.config();

const app = express();

app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('MongoDB connected!');
    })
    .catch(() => {
        console.error('Connection error!');
    });

    const userSchema = new mongoose.Schema({
        username: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true }
    });

    const User = mongoose.model('User', userSchema);

app.get('/', async (req, res) => {
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

        if (existingUser) {
            return res.status(400).json({ message: "Email already exists!" });
        }

        const hashPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashPassword });
        await user.save();
        
        res.status(200).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ message: 'Error registering user!' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const loginUser = await User.findOne({ email });

        if (!loginUser) throw new Error("Email already exists!");

        const isMatch = await bcrypt.compare(password, loginUser.password);

        if (!isMatch) throw new Error("Email or password is incorrect!");
        
        res.status(200).json({ message: 'Login successfull!' });
    } catch (error) {
        res.status(500).json({ message: 'Error login user!' });
    }
});

const PORT = 5000;
const HOST = 'localhost';

app.listen(PORT, HOST, () => {
    console.log(`Server is running on port http://${HOST}:${PORT}`);
});