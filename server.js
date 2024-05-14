
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
// Middleware configurations
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Add this line to parse JSON request bodies

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

const csrfProtection = csurf({ cookie: false });

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after an hour'
   });

// Apply the rate limiter to all routes
app.use(limiter);


// Apply CSRF protection to all POST routes
app.get("/", csrfProtection, (req, res) => {
    console.log("Rendering index page with CSRF Token:", req.csrfToken());
    // Pass the CSRF token to the template
    res.render("index", {
        sessionId: req.sessionID,
        csrfToken: req.csrfToken()  // Ensure this is added
    });
});

app.get("/signup", csrfProtection, (req, res) => {
    console.log("Rendering signup page with CSRF Token:", req.csrfToken());
    res.render("signup", {
        csrfToken: req.csrfToken(),  // Pass CSRF token to the view
        sessionId: req.sessionID    // Only pass this if it's actually used in the view
    });
});

app.get("/index", csrfProtection, (req, res) => {
    console.log("CSRF Token:", req.csrfToken());
    console.log("Rendering index page");
    res.render("index", {
        csrfToken: req.csrfToken(),
        sessionId: req.sessionID
        });
});

app.get("/login", csrfProtection, (req, res) => {
    console.log("CSRF Token:", req.csrfToken());
    //console.log("Rendering index page");
    res.render("login", {
         csrfToken: req.csrfToken(),
         sessionId: req.sessionID
         });
});

app.use((err, req, res, next) => {
    if (err.code === "EBADCSRFTOKEN") {
        // Handle CSRF token errors
        res.status(403);
        res.send("CSRF token mismatch, please refresh the page or try again.");
    } else {
        next(err);
    }
});

app.use(function(req, res, next) {
    // Make sessionId available to all views
    res.locals.sessionId = req.sessionID;
    next();
});

app.get("/editpost", (req, res) => {
    console.log("Rendering editpost page");
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
app.use(express.json()); // Add this line to parse JSON request bodies

app.post('/posts',csrfProtection, async (req, res) => {
    const { title, body } = req.body;
    const userId = req.session.userId; // Get the user ID from the session

    if (!userId) {
        // If the user is not logged in (no user ID in the session), return an error
        return res.status(401).json({ error: 'User not authenticated' });
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
    const searchTerm = req.query.searchTerm; // Assuming searchTerm is passed as a query parameter
    console.log('Search term:', searchTerm); // Log the search term

    try {
        let query = `
            SELECT posts.*, users.username
            FROM posts
            INNER JOIN users ON posts.user_id = users.id
        `;

        if (searchTerm) {
            console.log('Applying search filter'); // Log that a search filter is being applied
            query += `
                WHERE posts.title ILIKE $1
                OR posts.content ILIKE $1
                OR users.username ILIKE $1
            `;
            const result = await pool.query(query, [`%${searchTerm}%`]);
            console.log('Search results:', result.rows); // Log the search results
            const posts = result.rows;
            res.json(posts);
        } else {
            console.log('Fetching all posts'); // Log that all posts are being fetched
            const result = await pool.query(query);
            console.log('All posts:', result.rows); // Log all posts
            const posts = result.rows;
            res.json(posts);
        }
    } catch (error) {
        console.error('Error retrieving posts:', error); // Log the error
        res.status(500).json({ error: 'An error occurred while retrieving the posts.' });
    }
});


app.delete('/posts/:id', async (req, res) => {
    const postId = req.params.id;
    const userId = req.session.userId; // Get the user ID from the session

    if (!userId) {
        // If the user is not logged in (no user ID in the session), return an error
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        // Retrieve the post from the database
        const query = 'SELECT * FROM posts WHERE id = $1';
        const result = await pool.query(query, [postId]);
        const post = result.rows[0];

        if (!post) {
            // If the post doesn't exist, return an error
            return res.status(404).json({ error: 'Post not found' });
        }

        if (post.user_id !== userId) {
            // If the user ID of the post doesn't match the logged-in user ID, return an error
            return res.status(403).json({ error: 'Unauthorized' });
        }

        // Delete the post from the database
        const deleteQuery = 'DELETE FROM posts WHERE id = $1';
        await pool.query(deleteQuery, [postId]);

        res.sendStatus(200);
    } catch (error) {
        console.error('Error deleting post:', error);
        res.status(500).json({ error: 'An error occurred while deleting the post.' });
    }
});
app.get('/posts/:id', async (req, res) => {
    const postId = req.params.id;
    const userId = req.query.userId;

    console.log('Retrieving post with ID:', postId);
    console.log('User ID:', userId);

    try {
        const query = 'SELECT * FROM posts WHERE id = $1';
        const result = await pool.query(query, [postId]);
        const post = result.rows[0];

        if (!post) {
            console.log('Post not found');
            return res.status(404).json({ error: 'Post not found' });
        }

        if (post.user_id !== parseInt(userId)) {
            console.log('Unauthorized access');
            return res.status(403).json({ error: 'Unauthorized' });
        }

        res.json(post);
    } catch (error) {
        console.error('Error retrieving post:', error);
        res.status(500).json({ error: 'An error occurred while retrieving the post.' });
    }
});


app.get('/user', (req, res) => {
    const userId = req.session.userId;
    console.log('User ID in session:', userId);

    if (userId) {
        res.json({ id: userId });
    } else {
        res.status(401).json({ error: 'User not authenticated' });
    }
});

app.put('/posts/:id', async (req, res) => {
    const postId = req.params.id;
    const { title, body } = req.body;
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).json({ error: 'User not authenticated' });
    }

    try {
        const query = 'UPDATE posts SET title = $1, content = $2 WHERE id = $3 AND user_id = $4 RETURNING *';
        const values = [title, body, postId, userId];

        const result = await pool.query(query, values);
        const updatedPost = result.rows[0];

        if (!updatedPost) {
            return res.status(403).json({ error: 'Unauthorized' });
        }

        res.json(updatedPost);
    } catch (error) {
        console.error('Error updating post:', error);
        res.status(500).json({ error: 'An error occurred while updating the post.' });
    }
});

app.post('/login',csrfProtection, (req, res, next) => {
    console.log("Login attempt received");
    console.log("Email:", req.body.email);
    console.log("Password:", req.body.password);
    console.log("OTP:", req.body.otp);

    const { email, password, otp } = req.body;
    const sanitizedEmail = sanitizeInput(email);
    const sanitizedPassword = sanitizeInput(password);
    const sanitizedOtp = sanitizeInput(otp);

    // Query the database for the user
    pool.query('SELECT * FROM users WHERE email = $1', [sanitizedEmail], (error, results) => {
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

            // Generate the OTP on the server for comparison
            const serverOtp = speakeasy.totp({
                secret: user.secret,
                encoding: 'base32'
            });

            console.log("Server-generated OTP:", serverOtp);

            // Verify the OTP
            const verified = speakeasy.totp.verify({
                secret: user.secret,
                encoding: 'base32',
                token: otp,
            });

            if (!verified) {
                console.log("OTP verification failed");
                return res.status(401).send('OTP verification failed');
            }

            console.log("Login successful");
            // Store the userId in the session
            req.session.userId = user.id;
            // Save the session before redirecting
            req.session.save(function (err) {
                if (err) return next(err);
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
    console.log('Signup request received');
    console.log('Request body:', req.body);

    const { username, email, password } = req.body;
    const sanitizedUsername = sanitizeInput(username);
    const sanitizedEmail = sanitizeInput(email);
    const sanitizedPassword = sanitizeInput(password);

    try {
        // Check if username or email already exists in the database
        console.log('Checking if username or email already exists');
        const userCheck = 'SELECT id FROM users WHERE username = $1 OR email = $2';
        const userResult = await pool.query(userCheck, [username, email]);

        if (userResult.rows.length > 0) {
            console.log('Username or Email already exists');
            return res.status(400).json({ error: 'Username or Email already exists' });
        }

        // If checks pass, proceed to create new user
        console.log('Creating user:', username, email);
        
        // Hash the password
        const hashedPassword = await bcrypt.hash(sanitizedPassword, saltRounds);
        console.log('Password hashed successfully');
        console.log('Password hashed successfully');

        // Generate a shorter secret key for 2FA
        const secret = speakeasy.generateSecret({length: 8});

        // Insert the user into the database with the hashed password and secret key
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
        console.error('Signup error:', error);
        res.status(500).json({ error: 'An unexpected error occurred during signup.' });
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

console.log('Database URL:', process.env.DATABASE_URL);

// Test query to check database connection
pool.query('SELECT NOW()', (err, res) => {
 if (err) {
   console.error('Database connection error:', err);
 } else {
   console.log('Database connection successful');
 }
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

