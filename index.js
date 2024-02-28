require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mysql = require('mysql')
const argon2 = require('argon2')

/*

const db = mysql.createConnection({
    'host': process.env.DATABASE_HOST,
    'user': process.env.DATABASE_USER,
    'password': process.env.DATABASE_PASSWORD,
    'database': process.env.DATABASE
})

db.connect((error) => {
    if(error) {
        console.log(error)
    } else {
        console.log("Connected to database!")
    }
})
*/

app.use(express.json())

// Add GET responses for the website pages here
//app.get("/", (req, res) => {
//
//})




const port = 3000
app.listen(port)
console.log("Now listening on port " + port + ". ")