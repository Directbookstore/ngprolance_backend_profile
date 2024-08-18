const express = require('express');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static('public'));

// Serve the index.html file at the root URL
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Authorization middleware
const authenticateToken = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Register new user
app.post('/api/register', async (req, res) => {
    const { first_name, last_name, website, professional_title, email, bio, skills, portfolio, password } = req.body;

    try {
        const salt = await bcrypt.genSalt(10);
        const password_hash = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            `INSERT INTO users (first_name, last_name, website, professional_title, email, bio, skills, portfolio, password_hash) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
            [first_name, last_name, website, professional_title, email, bio, skills, JSON.stringify(portfolio), password_hash]
        );

        const token = jwt.sign({ id: newUser.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// User login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
        
        if (user.rows.length === 0) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.rows[0].password_hash);
        
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Get user profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    const { id } = req.user;

    try {
        const user = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
        res.json(user.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    const { first_name, last_name, website, professional_title, bio, skills, portfolio } = req.body;
    const { id } = req.user;

    try {
        await pool.query(
            `UPDATE users SET first_name = $1, last_name = $2, website = $3, professional_title = $4, bio = $5, skills = $6, portfolio = $7 WHERE id = $8`,
            [first_name, last_name, website, professional_title, bio, skills, JSON.stringify(portfolio), id]
        );
        res.send('Profile updated');
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
