

const express = require("express");
const app = express();
const port = 4000;
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const saltRounds = 10;
require('dotenv').config();

app.set('view engine', 'ejs');

const session = require('express-session');
// Configure the rate limiter


const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 1000, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after an hour'
   });

// Apply the rate limiter to all routes
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

app.use(function(req, res, next) {
    // Make sessionId available to all views
    res.locals.sessionId = req.sessionID;
    next();
});


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





app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Add this line to parse JSON request bodies

app.post('/posts', async (req, res) => {
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
    try {
        const query = 'SELECT * FROM posts';
        const result = await pool.query(query);
        const posts = result.rows;

        res.json(posts);
    } catch (error) {
        console.error('Error retrieving posts:', error);
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
    console.log('Signup request received'); // Log when a signup request is received
    console.log('Request body:', req.body); // Debug statement to log the request body

    const { username, email, password } = req.body;
    console.log('Received data:', { username, email, password }); // Log received data

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log('Password hashed successfully'); // Log successful password hashing

        // Insert the user into the database with the hashed password and unhashed password
        const query = 'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)';
        const values = [username, email, password]; // Include the unhashed password

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

console.log('Database URL:', process.env.DATABASE_URL);


const { Pool } = require('pg');
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});


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

