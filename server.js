const express = require("express")
const app = express()

app.set('view engine', 'ejs')

app.get("/", (req, res) => {
	res.redirect("index");
});

app.get("/index", (req, res) => {
	res.render("index");
});

app.get("/editpost", (req, res) => {
	res.render("editpost");
});

app.get("/newpost", (req, res) => {
	res.render("newpost");
});

//tests
app.listen(4000)