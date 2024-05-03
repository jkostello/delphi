require('dotenv').config()

const express = require('express')
const session = require('express-session')
const jwt = require('jsonwebtoken')
const mysql = require('mysql')
const argon2 = require('argon2')
const path = require('path')

const strDecoder = new TextDecoder('utf-8')

const db = mysql.createConnection({
    'host': process.env.DATABASE_HOST,
    'user': process.env.DATABASE_USER,
    'password': process.env.DATABASE_PASSWORD,
    'database': process.env.DATABASE
})

db.connect((error) => {
    if(error) {
        console.error(error)
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
    db.query('DELETE FROM users WHERE user_email = ?', [email], async (err, ress) => {
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
            console.error("The following error has been encountered: " + authFailReason) // Replace with actual error handling
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
    
    db.query('SELECT user_email FROM users WHERE user_email = ?', [email], async (error, ress) => {
        if (error) {
            console.error(error)
        } 
        else if (ress.length > 0) {
            return res.json({ result: 0, reason: "This email is already in use" })
        } 
        else if (password !== password_confirm) {
            return res.json({ result: 0, reason: "Passwords do not match!" })
        }

        const passwordHash = await argon2.hash(password)
        db.query('INSERT INTO users SET ?', { username: name, user_email: email, password_hash: passwordHash }, (err, ress) => {
            if (err) {
                console.error(err)
                return res.json({ result: 0, reason: "Database error" })
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

    db.query('SELECT password_hash FROM users WHERE user_email = ?', [email], async (error, ress) => {
        if (error) {
            console.error(error)
                return callback({ 'authenticated': false, 'other_info': error })
        }
        if (ress.length === 0) {
            return callback({ 'authenticated': false, 'other_info': 'email not associated with account' })
        }
        
        try {
            if (await argon2.verify(ress[0].password_hash, password)) {
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
    db.query('UPDATE users SET token = ? WHERE user_email = ?', [refreshToken, reqInput.email], async (error, res) => {
        if (error) {
            console.error(error)
            // Add error handling
        }
    })
}

app.get('/privileged', (req, res) => {
    const cookies = req.headers.cookie
    getCookie(cookies, 'accessToken', function(authToken) {
        try {
            if (typeof authToken === 'undefined') {
                res.redirect('/login')
            }
            else {
                // Verify provided Access Token
                let isVerified = verifyAccessToken(authToken)
                if (isVerified) {
                    res.status(200).sendFile(path.join(__dirname, "views/privileged.html"))
                } else {
                    // Try to renew Access Token
                    getCookie(cookies, 'refreshToken', function(rfToken) {
                        if (typeof rfToken === 'undefined' || rfToken === null) {
                            res.redirect('/login')
                        }
                        else {
                            let isVerified = verifyRefreshToken(rfToken)
                            if (isVerified) {
                                renewAccessToken(rfToken, function(newToken) {
                                    if (typeof newToken !== 'undefined' || newToken.success === 0) {
                                        res.cookie('accessToken', newToken.token).redirect('/privileged')
                                    } else {
                                        console.error("Token failed to generate")
                                        res.status(500).send("Failed to authenticate!")
                                    }
                                })
                            } else {
                                res.redirect('login')
                            }
                        }
                    })
                }
            }
        } catch (e) {
            res.status(500).send("Unknown error encountered!")
            console.error("Error in privileged GET: " + e)
        }

    })
})

// Client should send a request with JSON holding the data
app.post('/add-pass', (req, res) => {
    const authHeader = req.headers.authorization
    const data = req.body

    try {
        if (typeof authHeader === 'undefined') {
            res.sendStatus(400)
        }
        else if (authHeader.startsWith('Bearer ')) {
            // Verify provided Access Token
            let token = authHeader.substring(7, authHeader.length)
            let isVerified = verifyAccessToken(token)
            if (isVerified) {
                // Add password
                getUserID(token, function(user_id) {
                    if (user_id !== undefined) {
                        addPassword(user_id, data, function(resultStatus) {
                            if (resultStatus === 1) {
                                res.sendStatus(200)
                            } else {
                                res.sendStatus(500)
                                }
                        })
                    }
                })

            } else {
                res.sendStatus(401)
            }
        }
    } catch (e) {
        res.status(500).send("Unknown error encountered!")
        console.error("Error in privileged GET: " + e)
    }
})

app.get('/get-pass', (req, res) => {
    let authHeader = req.headers.authorization

    try {
        if (typeof authHeader === 'undefined') {
            res.sendStatus(400)
        }
        else if (authHeader.startsWith('Bearer ')) {
            // Verify provided Access Token
            let token = authHeader.substring(7, authHeader.length)
            let isVerified = verifyAccessToken(token)
            if (isVerified) {
                // Get passwords and send them with JSON
                getUserID(token, function(user_id) {
                    if (user_id !== undefined) {
                        getPasswords(user_id, function(passwords) {
                            res.setHeader('Content-Type', 'application/json')
                            res.status(200).send(JSON.stringify(passwords))
                        })
                    }
                })

            } else {
                res.sendStatus(401)
            }
        }
    } catch (e) {
        res.status(500).send("Unknown error encountered!")
        console.error("Error in privileged GET: " + e)
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
        console.error("Error renewing access token: " + e)
    }

})

async function getCookie(cookies, name, callback) {
    if (cookies === undefined) {
        return callback(0)
    }
    let found = false
    const splitCookies = cookies.split('; ')
    splitCookies.forEach(cookie => {
        const [cookieName, cookieValue] = cookie.split('=')
        if (cookieName == name) {
            found = true
            return callback(cookieValue)
        }
    })
    if (!found) {
        return callback(0)
    }
}

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
    db.query('SELECT username FROM users WHERE token = ?', [refreshToken], async (error, res) => {
        if (error) {
            console.error("Error in renewAccessToken query: " + error)
            return callback( {'success': 0} )
        } else if (res.length == 0) {
            console.error("refreshToken not found in database!")
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

function getUserID(accessToken, callback) {
    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            console.error("Error verifying access token in getUserID: " + err)
            return callback(undefined)
        } else {
            db.query('SELECT user_id FROM users WHERE username = ?', [decoded.user], async (error, res) => {
                if (error) {
                    console.error('Error getting user_id: '+error)
                    return callback(undefined)
                } else if (res.length == 0) {
                    // user is not in the db
                    return callback(undefined)
                } else {
                    return callback(res[0].user_id)
                }
            })
        }
    })
}

// Will return a 1 if successful, or 0 for failure
async function addPassword(user_id, info, callback) {
    // Encrypt password before putting it into the database
    let ciphertext = await encrypt(user_id, info.password)
    let insert_data = [[user_id, info.username, ciphertext, info.website]]
    return db.query("INSERT INTO passwords (user_id, username, user_password, website) VALUES ?", [insert_data], async (error) => {
        if (error) {
            console.error("Error adding password to the database: " + error)
            return callback(0)
        } else {
            // Handle success
            return callback(1)
        }
    })
}

async function getPasswords(user_id, callback) {
    db.query("SELECT username, user_password, website FROM passwords WHERE user_id = ?", [user_id], async (error, res) => {
        if (error) {
            console.error("Error getting passwords from database: " + error)
            return callback({})
        } else if (res.length === 0) {
            return callback({})
        } else {
            const decrypted = []
            try {
                for (const currentValue of res) {
                    try {
                        currentValue.user_password = await decrypt(user_id, currentValue.user_password)
                        decrypted.push(currentValue)
                    }
                    catch {
                        return "Error"
                    }
                }
            }
            catch (error) {
                console.error("Error decrypting:", error)
            }
            return callback(decrypted)
        }
    })
}

async function encrypt(user_id, plaintext) {
    return new Promise((resolve, reject) => {
        getSalt(user_id, async function(key) {
            try {
                const payload = plaintext + " " + key;
                const result = await fetch('http://localhost:8000/encrypt', {
                    method: 'POST',
                    body: payload
                });
                const streamReader = result.body.getReader();
                const contents = await readStream(streamReader, "");
                resolve(contents);
            } catch (error) {
                reject(error);
            }
        });
    });
}

async function decrypt(user_id, ciphertext) {
    return new Promise((resolve, reject) => {
        getSalt(user_id, async function(key) {
            try {
                if (ciphertext === undefined || key === undefined) {
                    console.error("Undefined value in decrypt! Values:", ciphertext, key)
                    reject("Undefined")
                }
                else {
                    const payload = ciphertext + " " + key;
                    const result = await fetch('http://localhost:8000/decrypt', {
                        method: 'POST',
                        body: payload
                    });
                    const streamReader = result.body.getReader();
                    const contents = await readStream(streamReader, "");
                    resolve(contents);
                }
            } catch (error) {
                reject(error);
            }
        });
    });
}

async function readStream(reader, contents) {
    return new Promise((resolve, reject) => {
        function readChunk() {
            reader.read().then(({ done, value }) => {
                if (done) {
                    resolve(contents);
                    return;
                }
                contents += strDecoder.decode(value);
                readChunk();
            }).catch(reject);
        }
        readChunk();
    });
}

function getSalt(user_id, callback) {
    db.query("SELECT password_hash FROM users WHERE user_id = ?", [user_id], async (error, res) => {
        if (error) {
            console.error("Error getting password hash: " + error)
            return callback(0)
        } else if (res.length !== 1) {
            return callback(0)
        } else {
            // Extract salt from hash string
            const salt = res[0].password_hash.substring(31, 53)
            return callback(salt)
        }
    })
}

const port = 4000
app.listen(port)
console.log("Now listening on port " + port + ". ")