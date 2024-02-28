require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')
const mysql = require('mysql')
const argon2 = require('argon2')

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

app.use(express.json())

// Add all pages that need authentication to work here

app.post("/token", (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.sendStatus(401);
    // ADD if refresh token db does not have provided token, return a status of 403
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const accessToken = generateAccessToken({ name: user.name })
        res.json({ accessToken: accessToken });
    })
});


// Logout page removes the refresh token from the db and adds the current access token to a denylist (TODO)
app.delete("/logout", (req, res) => {
    updateDBRefreshToken(req.body, null, 'delete')
    res.sendStatus(204);
})

// Remove account from db
app.delete("/account/delete", (req, res) => {
    const email = req.body.email
    db.query('DELETE FROM users WHERE email = ?', [email], async (err, ress) => {
        console.log(ress)
        return res.json({ result: ress })
    })
})

// Login page
app.post("/login", (req, res) => {

    authenticateUser(req.body, function(result) {

    // Handle the result of the authentication
    if (result.authenticated === false) {
        // Handle unauthenticated login attempt
        const authFailReason = result.other_info
        console.log(typeof authFailReason)

        if (authFailReason === 'email not associated with account' || authFailReason === 'incorrect password'){
            // Replace this with what the user should actually see
            res.json({ reason: 'The provided email or password is incorrect'} )
        } else {
            // This should only be reached if there is an error with the database or the password verification
            console.log("The following error has been encountered: " + authFailReason) // Replace with actual error handling
            res.json({ reason: 'An error has been encountered!' })
        }
    }
    else {
        const username = req.body.username;
        const user = { name: username }

        const accessToken = generateAccessToken(user);
        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
        // TODO add refresh token to db
        updateDBRefreshToken(req.body, refreshToken, 'update')
        res.json({ accessToken: accessToken, refreshToken: refreshToken });
    }


    })

})

app.post("/register", (req, res) => {
    const { name, email, password, password_confirm } = req.body
    
    db.query('SELECT email FROM users WHERE email = ?', [email], async (error, ress) => {
        if (error) {
            console.log(error)
        }

        // Replace these res.render pages with what should actually happen
        if (ress.length > 0) {
            return res.json({ registration_result: "This email is already in use" })
            //return res.render('register', {
            //    message: 'This email is already in use.'
            //})
        } else if (password !== password_confirm) {
            return res.json({ registration_result: "Passwords do not match!" })
            //return res.render('register', {
            //    message: 'Passwords do not match!'
            //})
        }

        const passwordHash = await argon2.hash(password)
        db.query('INSERT INTO users SET?', { username: name, email: email, password: passwordHash }, (err, ress) => {
            if (error) {
                console.log(error)
                return res.json({ registration_result: "Database error" })
            } else {
                res.json({ registration_result: "Successfully registered!" })
                //return res.render('register', {message: "User registered!"})
            }
        })
    })
})


function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
}


// Returns object with boolean for if the user is authenticated and other information
function authenticateUser({ email, password }, callback) {

    // Validate email and password here

    db.query('SELECT password FROM users WHERE email = ?', [email], async (error, ress) => {
        if (error) {
            console.log(error)
                return callback({ 'authenticated': false, 'other_info': error })
        }
        if (ress.length === 0) {
            return callback({ 'authenticated': false, 'other_info': 'email not associated with account' })
        }
        
        try {
            if (await argon2.verify(ress[0].password, password)) {
                return callback({ 'authenticated': true, 'other_info': null })
              
            } else {
                return callback({ 'authenticated': false, 'other_info': 'incorrect password' })
            }
          } catch (err) {
            return callback({ 'authenticated': false, 'other_info': err })
          }
        
    })
}

// reqInput should be the req.body
// alterType should be 'update' or 'delete' to either add a refresh token or set the entry to NULL
// if alterType === 'delete', refreshToken should be null
function updateDBRefreshToken(reqInput, refreshToken, alterType) {
    // Refresh tokens should probably be in a separate database
    db.query('UPDATE users SET refresh_token = ? WHERE email = ?', [refreshToken, reqInput.email], async (error, res) => {
        if (error) {
            console.log(error)
            // Add error handling
        } else {
            if (alterType === 'update') console.log("Refresh token changed for user " + reqInput.name)
            if (alterType === 'delete') console.log("Refresh token deleted for user " + reqInput.name)
        }
    })
}


const port = 4000
app.listen(port)
console.log("Now listening on port " + port + ". ")