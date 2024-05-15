const speakeasy = require('speakeasy');
const express = require("express");
const app = express();
const port = 4000;
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const bcrypt = require('bcrypt');
const csurf = require('csurf');
const saltRounds = 10;
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 3600000
    }
}));

const csrfProtection = csurf({ cookie: false });

app.use(csrfProtection);

app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    res.locals.sessionId = req.sessionID;
    next();
});

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: 'Too many requests from this IP, please try again after an hour'
});

app.use(limiter);

app.set('view engine', 'ejs');

app.get("/", csrfProtection, (req, res) => {
    res.render("index", {
        sessionId: req.sessionID,
        csrfToken: req.csrfToken()  
    });
});

app.get("/signup", csrfProtection, (req, res) => {
    res.render("signup", {
        csrfToken: req.csrfToken(),  // Pass CSRF token to the view
        sessionId: req.sessionID    
    });
});

app.get("/index", csrfProtection, (req, res) => {
    res.render("index", {
        csrfToken: req.csrfToken(),
        sessionId: req.sessionID
    });
});

app.get("/login", csrfProtection, (req, res) => {
    res.render("login", {
        csrfToken: req.csrfToken(),
        sessionId: req.sessionID
    });
});

app.get("/editpost", (req, res) => {
    res.render("editpost");
});


function sanitizeInput(input) {
    // Remove or escape characters that are commonly used in SQL injection attacks
    return input.replace(/[\0\x08\x09\x1a\n\r"'\\\x00-\x1f]/g, function (char) {
        switch (char) {
            case '\0':
            case '\x08':
            case '\x09':
            case '\x1a':
            case '\n':
            case '\r':
            case "'":
            case '"':
            case '\\':
            case '\x00':
            case '\x1f':
                return '';
            default:
                return '\\' + char;
        }
    });
}



app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); 

app.post('/posts',csrfProtection, async (req, res) => {
    const { title, body } = req.body;
    const userId = req.session.userId;

    console.log('Title:', title); // Log the title
    console.log('Body:', body); // Log the body

    if (!userId) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    if (!title || !body) {
        return res.status(400).json({ error: 'Title and body are required' });
    }

    try {
        const query = 'INSERT INTO posts (user_id, title, content) VALUES ($1, $2, $3) RETURNING *';
        const values = [userId, title, body];

        const result = await pool.query(query, values);
        const createdPost = result.rows[0];

        res.json(createdPost);
    } catch (error) {
        console.error('Error creating post:', error);
        res.status(500).json({ error: 'An error occurred while creating the post.' });
    }
});


app.get('/posts', async (req, res) => {
    const searchTerm = req.query.searchTerm; // Get the search term from the query string
    console.log('Search term:', searchTerm); // Log the search term

    try {
        let query = `
            SELECT posts.*, users.username
            FROM posts
            INNER JOIN users ON posts.user_id = users.id
        `;

        if (searchTerm) {
            query += `
                WHERE posts.title ILIKE $1
                OR posts.content ILIKE $1
                OR users.username ILIKE $1
            `;
            const result = await pool.query(query, [`%${searchTerm}%`]);
            const posts = result.rows;
            res.json(posts);
        } else {
            const result = await pool.query(query);
            const posts = result.rows;
            res.json(posts);
        }
    } catch (error) {
        console.error('Error retrieving posts:', error);
        res.status(500).json({ error: 'An error occurred while retrieving the posts.' });
    }
});

app.delete('/posts/:id', async (req, res) => {
    const postId = req.params.id;
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        const query = 'SELECT * FROM posts WHERE id = $1';
        const result = await pool.query(query, [postId]);
        const post = result.rows[0];

        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        if (post.user_id !== userId) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        const deleteQuery = 'DELETE FROM posts WHERE id = $1';
        await pool.query(deleteQuery, [postId]);

        res.sendStatus(200);
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ error: 'An error occurred while deleting the post.' });
    }
});// Route to retrieve a specific post by its ID
app.get('/posts/:id', async (req, res) => {
    // Extract the post ID from the request parameters
    const postId = req.params.id;
    // Extract the user ID from the request query parameters
    const userId = req.query.userId;

    
    try {
        // SQL query to fetch the post with the specified ID
        const query = 'SELECT * FROM posts WHERE id = $1';
        const result = await pool.query(query, [postId]);
        const post = result.rows[0];

        // Check if the post exists
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }

        // Check if the current user is authorized to access the post
        if (post.user_id!== parseInt(userId)) {
            console.log('Unauthorized access');
            return res.status(403).json({ error: 'Unauthorized' });
        }

        // If the post exists and the user is authorized, return the post
        res.json(post);
    } catch (error) {
        console.error('Error retrieving post:', error);
        res.status(500).json({ error: 'An error occurred while retrieving the post.' });
    }
});



// Route to retrieve the user ID from the session
app.get('/user', (req, res) => {
    // Extract the user ID from the session
    const userId = req.session.userId;

    // If the user ID exists in the session, return it
    if (userId) {
        res.json({ id: userId });
    } else {
        // If the user ID does not exist, return an error indicating the user is not authenticated
        res.status(401).json({ error: 'User not authenticated' });
    }
});

// Route to update a specific post by its ID
app.put('/posts/:id', async (req, res) => {
    // Extract the post ID from the request parameters
    const postId = req.params.id;
    // Extract the title and body from the request body
    const { title, body } = req.body;
    // Extract the user ID from the session
    const userId = req.session.userId;

    // Check if the user is authenticated
    if (!userId) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        // SQL query to update the post with the specified ID, title, and body
        const query = 'UPDATE posts SET title = $1, content = $2 WHERE id = $3 AND user_id = $4 RETURNING *';
        const values = [title, body, postId, userId];

        const result = await pool.query(query, values);
        const updatedPost = result.rows[0];

        // Check if the post was successfully updated
        if (!updatedPost) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        // If the post was successfully updated, return the updated post
        res.json(updatedPost);
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).json({ error: 'An error occurred while updating the post.' });
    }
});

// Route to handle login requests with CSRF protection
app.post('/login',csrfProtection, (req, res, next) => {
    console.log("Login attempt received");
    console.log("Email:", req.body.email);
    console.log("Password:", req.body.password);
    console.log("Captcha:", req.body.captcha);
    console.log("OTP:", req.body.otp);
    console.log("CSRF Token:", req.csrfToken());

    // Destructure and sanitize input from the request body
app.post('/login', csrfProtection, (req, res, next) => {
    const { email, password, captcha, otp } = req.body;
    const sanitizedEmail = sanitizeInput(email);
    const sanitizedPassword = sanitizeInput(password);
    const sanitizedOtp = sanitizeInput(otp);

    // Verify the captcha
    if (captcha!== req.session.captcha) {
        console.log("Captcha verification failed");
        return res.render('index', { error: 'Captcha verification failed', csrfToken: req.csrfToken() });
    }

    // Query the database to find the user by email
    pool.query('SELECT * FROM users WHERE email = $1', [sanitizedEmail], (error, results) => {
        if (error) {
            return res.render('index', { error: 'Database query error', csrfToken: req.csrfToken() });
        }

        if (results.rows.length === 0) {
            return res.render('index', { error: 'No user found with the provided email', csrfToken: req.csrfToken() });
        }

        // Retrieve the first user from the query results
        const user = results.rows[0];
        // Compare the provided password with the hashed password stored in the database
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) {
                return res.render('index', { error: 'Error comparing passwords', csrfToken: req.csrfToken() });
            }

            if (!isMatch) {
                return res.render('index', { error: 'Invalid email or password', csrfToken: req.csrfToken() });
            }

            const serverOtp = speakeasy.totp({
                secret: user.secret,
                encoding: 'base32'
            });

            const verified = speakeasy.totp.verify({
                secret: user.secret,
                encoding: 'base32',
                token: otp,
            });

            if (!verified) {
                return res.render('index', { error: 'Invalid OTP', csrfToken: req.csrfToken() });
            }

            // If all verifications pass, set the user ID in the session and redirect to the home page
            req.session.userId = user.id;
            req.session.save(err => {
                if (err) {
                    return next(err);
                }
                res.redirect('/home');
            });
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

app.get('/home', csrfProtection, (req, res) => {
    res.render('home', { csrfToken: req.csrfToken() });
});

app.post('/signout', (req, res, next) => {
    req.session.destroy(err => {
        if (err) {
            next(new Error('Error signing out'));
        } else {
            res.clearCookie('connect.sid');
            res.redirect('/');
        }
    });
});

// Route to handle signup requests
app.post('/signup', async (req, res) => {
    console.log('Signup request received');
    console.log('Request body:', req.body);

    // Destructure and sanitize input from the request body
    const { username, email, password } = req.body;
    const sanitizedUsername = sanitizeInput(username);
    const sanitizedEmail = sanitizeInput(email);
    const sanitizedPassword = sanitizeInput(password);

    try {
        const userCheck = 'SELECT id FROM users WHERE username = $1 OR email = $2';
        const userResult = await pool.query(userCheck, [username, email]);

        if (userResult.rows.length > 0) {
            return res.status(400).json({ error: 'Username or Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(sanitizedPassword, saltRounds);
        const secret = speakeasy.generateSecret({ length: 8 });

        const query = 'INSERT INTO users (username, email, password, secret) VALUES ($1, $2, $3, $4) RETURNING id';
        const values = [sanitizedUsername, sanitizedEmail, hashedPassword, secret.base32];

        const result = await pool.query(query, values);
        const newUser = result.rows[0];
        console.log('User inserted into database:', newUser);

        // Send the secret key to the user's email or display it on the screen
        // This is a placeholder for the actual implementation
        console.log('Secret key:', secret.base32);

        res.json({ message: 'User created successfully', userId: newUser.id, secretKey: secret.base32 });
    } catch (error) {
        res.status(500).json({ error: 'An unexpected error occurred during signup.' });
    }
});




// Route to handle signout requests
app.get('/signout', (req, res) => {
    // Render the signout page
    res.render('signout');
});

// Middleware to handle errors globally
app.use((err, req, res, next) => {
    // Log the error stack trace for debugging
    console.error(err.stack);
    // Send a generic error message to the client
    res.status(500).send('Something broke!');
});

// Start the server
app.listen(port, () => {
    // Log the server's port
    console.log(`Server running at http://localhost:${port}`);
});

// Log the database URL for debugging
console.log('Database URL:', process.env.DATABASE_URL);

pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Database connection successful');
    }
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Database connection successful');
    }
});

// Middleware to handle errors globally
app.use((err, req, res, next) => {
    // Log the error stack trace for debugging
    console.error(err.stack);
    // Send a generic error message to the client
    res.status(500).send('Something broke!');
});
