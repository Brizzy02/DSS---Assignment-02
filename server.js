

const express = require("express");
const app = express();
const port = 4000;
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const saltRounds = 10;

app.set('view engine', 'ejs');

const session = require('express-session');
// Configure the rate limiter


const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 300, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after an hour'
   });

// Apply the rate limiter to all routess
app.use(limiter);

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
        httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
        maxAge: 3600000 // Session expires after 1 hour (in milliseconds)
    }
}));


app.get("/signup", (req, res) => {
    console.log("Rendering signup page");
    res.render("signup"); // Make sure this matches the name of your EJS file
});


app.get("/", (req, res) => {
    console.log("Rendering index page");
    res.render("index", {sessionId: req.sessionID});
});

app.get("/index", (req, res) => {
    console.log("Rendering index page");
    res.render("index");
});

app.get("/editpost", (req, res) => {
    console.log("Rendering editpost page");
    res.render("editpost");
});

app.get("/newpost", (req, res) => {
    console.log("Rendering newpost page");
    res.render("newpost");
});

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));


app.post('/login', (req, res, next) => {
    console.log("Login attempt received");
    console.log("Email:", req.body.email);
    console.log("Password:", req.body.password); // Be cautious with logging passwords
    console.log("Captcha:", req.body.captcha);

    const { email, password, captcha } = req.body;

    // Check if the captcha entered by the user matches the one stored in the session
    if (captcha !== req.session.captcha) {
        console.log("Captcha verification failed");
        return res.status(401).send('Captcha verification failed');
    }

    // Query the database for the user
    pool.query('SELECT * FROM users WHERE email = $1', [email], (error, results) => {
        if (error) {
            console.error("Database query error:", error);
            return res.status(500).send('Database query error');
        }

        if (results.rows.length === 0) {
            console.log("No user found with the provided email");
            return res.status(401).send('No user found with the provided email');
        }

        const user = results.rows[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                console.error("Error comparing passwords:", err);
                return res.status(500).send('Error comparing passwords');
            }

            if (!isMatch) {
                console.log("Password does not match");
                return res.status(401).send('Password does not match');
            }

            console.log("Login successful");
            res.redirect('/home');
        });
    });
});



const svgCaptcha = require('svg-captcha');

app.get('/captcha', (req, res) => {
    const captcha = svgCaptcha.create();
    req.session.captcha = captcha.text;

    res.type('svg');
    res.status(200).send(captcha.data);
});



app.get('/home', (req, res) => {
    console.log("Rendering home page");
    res.render('home');
});

app.post('/signout', (req, res, next) => {
    req.session.destroy(err => {
        if (err) {
            next(new Error('Error signing out'));
        } else {
            res.clearCookie('connect.sid');
            res.redirect('/signout');
        }
    });
});


app.post('/signup', async (req, res) => {
    console.log('Signup request received'); // Log when a signup request is received
    console.log('Request body:', req.body); // Debug statement to log the request body

    const { username, email, password } = req.body;
    console.log('Received data:', { username, email, password }); // Log received data

    try {
        // First, check if the username already exists
        const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (userExists.rows.length > 0) {
            return res.status(409).json({ error: 'Username already exists.' }); // 409 Conflict
        }
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log('Password hashed successfully'); // Log successful password hashing

        // Insert the user into the database with the hashed password and unhashed password
        const query = 'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)';
        const values = [username, email, hashedPassword];
        await pool.query(query, values);
        console.log('User inserted into database'); // Log successful user insertion

        res.json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Error during signup:', error); // Log any errors
        res.status(500).json({ error: 'An error occurred during signup.' });
    }
});



app.get('/signout', (req, res) => {
    res.render('signout');
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});


require('dotenv').config(); 
const { Pool } = require('pg');

const pool = new Pool({
 connectionString: process.env.DATABASE_URL,
});


app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

