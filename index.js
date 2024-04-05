const express = require('express')
const path = require('path')
const httpProxy = require('http-proxy')

const SERVER_URL = "127.0.0.1"
const PROXY_PORT = 4000

const app = express()
const proxy = httpProxy.createProxyServer()

const forwardPostRequests = (req, res, next) => {
    // Forward POST requests to auth server
    if (req.method === 'POST') {
        let forwardTarget = req.headers.referer.split(PORT).slice(-1)[0]
        let fullForwardTarget = "http://"+SERVER_URL+":"+PROXY_PORT+forwardTarget
        
        proxy.web(req, res, { target: fullForwardTarget }, err => {
            console.log("Error while forwarding POST request:", err)
            res.status(500).send("Proxy error")
        })
    }
    else {
        next()
    }
}

app.use(express.json())
app.use(express.static(__dirname + '/public'))

// Add GET responses for the website pages here
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "/views/index.html"))
})

app.get("/login", (req, res) => {
    res.sendFile(path.join(__dirname, "/views/login.html"))
})

app.get("/register", (req, res) => {
    res.sendFile(path.join(__dirname, "/views/register.html"))
})

app.use(forwardPostRequests)

const PORT = 3000
app.listen(PORT)
console.log("Now listening on port " + PORT + ". ")