<?php
//retrive form data
$website = $_POST['website']
$username = $_POST['username']
$password = $_POST['password']

$servername = "localhost";
$db_username = "your_username";
$db_password = "your_password";
$dbname = "your_database";

//create connection
$conn = new mysqli($servername, $db_username, $db_password, $dbname);

//check connection
if($conn -> connect_error) {
    die("Connection failed: " . $conn->connect-error);

}

//Insert data into the database
$sql = "INSERT INTO passwords (website, username, password) VALUES ('$website', '$username', '$password')";

if ($conn->query($sql) ==true) {
    echo "Password saved successfully";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

// close connection
$conn->close();
?>