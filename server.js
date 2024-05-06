const express = require("express");
const app = express();
const port = 4000;

app.set('view engine', 'ejs');

app.get("/", (req, res) => {
    console.log("Rendering index page"); // Debugging statement
    res.render("index");

});

app.get("/index", (req, res) => {
    console.log("Rendering index page"); // Debugging statement
    res.render("index");

});

app.get("/editpost", (req, res) => {
    console.log("Rendering editpost page"); // Debugging statement
    res.render("editpost");

});

app.get("/newpost", (req, res) => {
    console.log("Rendering newpost page"); // Debugging statement
    res.render("newpost");

});


// Serve static files from the public directory
app.use(express.static('public'));

// Parse URL-encoded bodies (as sent by HTML forms)
app.use(express.urlencoded({ extended: true }));

// Debugging statement for POST request
app.post('/login', (req, res) => {
    console.log("Login attempt received"); // Debugging statement
    console.log("Email:", req.body.email); // Debugging statement
    console.log("Password:", req.body.password); // Debugging statement

    res.redirect('/home');
});

app.get('/home', (req, res) => {
    console.log("Rendering home page"); // Debugging statement
    res.render('home');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

app.post('/signout', (req, res) => {
    // Assuming you're using Express sessions
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Error signing out');
        }
        res.clearCookie('connect.sid'); // Clear the session cookie
        res.redirect('/signout'); // Redirect to the signout page
    });
});

// Add a route to render the signout.ejs page
app.get('/signout', (req, res) => {
    res.render('signout');
});


