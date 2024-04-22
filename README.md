# Server Setup Instructions

## Node.JS Server
1. Set database and token parameters in .env<br>
It should look something like this (with token secrets being a random string):<br>
>DATABASE=PasswordDatabase<br>
>DATABASE_HOST=localhost<br>
>DATABASE_USER=user<br>
>DATABASE_PASSWORD=pass
>
>ACCESS_TOKEN_SECRET=1234<br>
>REFRESH_TOKEN_SECRET=1234
2. Install Node.JS packages by running "npm install"
3. Start server with "npm run startDev_auth"

*If there are database errors, make sure that the database credentials in .env are correct and that the database is running.*

## Java Server
