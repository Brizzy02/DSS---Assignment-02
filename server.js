const express = require("express")
const app = express()

app,get('/', (req, res) =>{
    console.log("here")
    res.send("hi")
})

app.listen(3000)