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
2. Install Node.JS packages by running `npm install`
3. Start server with `npm run startDev_auth`

*If there are database errors, make sure that the database credentials in .env are correct and that the database is running.*

## Java Server
1. In terminal, navigate to Java folder in project
2. Run `javac *.java`
3. Start server with `java Java_server.java`


### To call encrypt/decrypt functions:
1. Make request to port 8000 with URI "/encrypt" or "/decrypt" depending on function requirement
2. In body of request, send password and key separated by a space:
>test_password test_key
3. If correct, the server will send back a message with the appropriate string

*If encountering the error "cannot find symbol", ensure the path to "java.exe" is added in local machine's PATH environmental variable*