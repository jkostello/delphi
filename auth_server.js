require('dotenv').config()

const express = require('express')
const session = require('express-session')
const jwt = require('jsonwebtoken')
const mysql = require('mysql')
const argon2 = require('argon2')
const path = require('path')

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

const app = express()

app.use(express.static(__dirname + '/public'))
app.use(express.json())
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false
}))

const accessTokenExpireTime = '15m'

// Add all pages that need authentication to work here

// TODO move unauthorized GET requests to another server

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "/views/index.html"))
})

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "/views/login.html"))
})

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "/views/register.html"))
})

// Logout page removes the refresh token from the db and adds the current access token to a denylist (TODO)
app.get("/logout", (req, res) => {
    updateDBRefreshToken(req.body, null, 'delete')
    let pastDate = 'expires=01-01-1970; '
    res.setHeader('Set-Cookie', ['accessToken=; '+pastDate, 'refreshToken=; '+pastDate])
    res.status(204).send("You have been successfully logged out.") // Replace with actual logout page
})

// Remove account from db
// Make it GET a page which has a form that asks for confirmation before sending a DELETE
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

        if (authFailReason === 'email not associated with account' || authFailReason === 'incorrect password'){
            // Replace this with what the user should actually see
            res.json({ result: 0, reason: 'The provided email or password is incorrect'} )
        } else {
            // This should only be reached if there is an error with the database or the password verification
            console.log("The following error has been encountered: " + authFailReason) // Replace with actual error handling
            res.json({ result: 0, reason: 'An error has been encountered!' })
        }
    }
    else {
        const username = req.body.username
        const user = { name: username }
        const remember_me = req.body.remember_me

        const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
        const accessToken = generateAccessToken(user, 1)
        updateDBRefreshToken(req.body, refreshToken, 'update')
        let rtHeader = 'refreshToken=' + refreshToken
        let atHeader = 'accessToken=' + accessToken

        if (remember_me === true) {
            const futureDate = '01-01-9999'
            rtHeader += '; Expires=' + futureDate
        }

        res.setHeader('Set-Cookie', [atHeader, rtHeader])
        res.json({ result: 1 })

        res.status(200).send()
    }


    })

})

app.post("/register", (req, res) => {
    const { name, email, password, password_confirm } = req.body
    
    db.query('SELECT email FROM users WHERE email = ?', [email], async (error, ress) => {
        if (error) {
            console.log(error)
        } 
        else if (ress.length > 0) {
            return res.json({ result: 0, reason: "This email is already in use" })
        } 
        else if (password !== password_confirm) {
            return res.json({ result: 0, reason: "Passwords do not match!" })
        }

        const passwordHash = await argon2.hash(password)
        db.query('INSERT INTO users SET?', { username: name, email: email, password: passwordHash }, (err, ress) => {
            if (error) {
                console.log(error)
                return res.json({ result: 0, reason: "Database error" })
            } 
            else {
                res.json({ result: 1, reason: "Successfully registered!" })
            }
        })
    })
})


// generatedFromLogin should be a 1 if it was generated from a successful login and a 0 otherwise
function generateAccessToken(user, generatedFromLogin) {
    let payload = {
        user: user,
        generatedFromLogin: generatedFromLogin
    }
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: accessTokenExpireTime })
}


// Returns object with boolean for if the user is authenticated and other information
function authenticateUser({ email, password }, callback) {

    // Validate email and password

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
// TODO
function updateDBRefreshToken(reqInput, refreshToken, alterType) {
    // Refresh tokens should probably be in a separate database
    db.query('UPDATE users SET refresh_token = ? WHERE email = ?', [refreshToken, reqInput.email], async (error, res) => {
        if (error) {
            console.log(error)
            // Add error handling
        }
    })
}

app.get('/privileged', (req, res) => {
    let authHeader = req.headers.authorization
    try {
        if (typeof authHeader === 'undefined') {
            res.sendFile(path.join(__dirname, "views/privileged_temp_page.html"))
        }
        else if (authHeader.startsWith('Bearer ')) {
            // Verify provided Access Token
            let token = authHeader.substring(7, authHeader.length)
            let isVerified = verifyAccessToken(token)
            if (isVerified) {
                res.status(200).sendFile(path.join(__dirname, "views/test_privileged_page.html"))
            } else {
                res.sendStatus(401)
            }
        }
    } catch (e) {
        res.status(500).send("Unknown error encountered!")
        console.error("Error in privileged GET: "+e)
    }
})

// Gets new access token using refresh token
app.get('/refresh-token', (req, res) => {
    let authHeader = req.headers.authorization
    try {
        if (typeof authHeader === 'undefined') {
            res.status(400).send("Invalid authorization header")
        }
        else if (authHeader.startsWith('Bearer ')) {
            // Verify provided Refresh Token
            let token = authHeader.substring(7, authHeader.length)
            let isVerified = verifyRefreshToken(token)
            if (isVerified) {
                renewAccessToken(token, function(newToken) {
                    if (typeof newToken !== 'undefined' || newToken.success === 0) {
                        let atHeader = 'accessToken=' + newToken.token
                        res.setHeader('Set-Cookie', atHeader)
                        res.status(200).send()
                    } else {
                        console.error("Token failed to generate")
                        res.status(500).send("Failed to authenticate!")
                    }
                })
            } 
            else {
                res.status(400).send("Invalid authorization header")
            }
        }
        else {
            res.status(400).send("Invalid authorization header")
        }
    } catch (e) {
        console.error("Error renewing access token: "+e)
    }

})

function verifyRefreshToken(refreshToken) {
    return jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err) => {
        if (err) {
            return false
        } else {
            return true
        }
    })
}

function verifyAccessToken(accessToken) {
    return jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err) => {
        if (err) {
            return false
        } else {
            return true
        }
    })
}

// Create a new access token with refresh token
function renewAccessToken(refreshToken, callback) {
    db.query('SELECT username FROM users WHERE refresh_token = ?', [refreshToken], async (error, res) => {
        if (error) {
            console.error("Error in renewAccessToken query: "+error)
            return callback( {'success': 0} )
        } else if (res.length == 0) {
            console.log("refreshToken not found in database!")
            return callback( {'success': 0} )
        } else {
            try {
                let newToken = generateAccessToken(res[0].username)
                return callback( {'success': 1, token: newToken} )
            } catch (e) {
                console.error('Error generating access token: '+e)
                return callback( {'success': 0} )
            }
        }
    })
}

const port = 4000
app.listen(port)
console.log("Now listening on port " + port + ". ")