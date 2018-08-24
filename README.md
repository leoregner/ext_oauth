# README
The purpose of this software is to use an existing application's user authentication database table to provide users access to other apps with the same credentials using the OAuth protocol.

## Getting Started
To run the application in a Docker container:

```
docker run -d -P hucskfjs/ext_oauth
```

## Environment Variables
*  `DB_HOST` = the IP address or host name of the MySQL database server
*  `DB_NAME` = the name of the database
*  `DB_USER` = the database user name
*  `DB_PASS` = the database user's password
*  `U_TABLE` = the name of the database table, which contains the user information
*  `USER_CO` = the name of the table column, which contains the unique user name/identifier
*  `PASS_CO` = the name of the table column, which contains the user's password
*  `PASSENC` = the method used for hashing the password; must be either `bcrypt`, `sha1`, `md5`, `nt` or `none`
*  `SCOPECO` = a comma separated list of table columns, whose values may be read by client applications; e.g. `first_name,last_name,birthday`

## Example Usage
Let's assume our user table looks like this:

| id | username | first_name | last_name | language | password                                                     |
|----|----------|------------|-----------|----------|--------------------------------------------------------------|
| 1  | john.doe | John       | Doe       | DE       | $2y$12$sIAGjUBSegJnB1R3SvI6XOVGpN/AIKnRBJdN9GeHkS29djOpADkNe |
| 2  | jane.doe | Jane       | Doe       | EN       | $2y$12$ICrmP19PYuriK2SoIe16qe0/qgVSZr.V92JzBYEddOQNRzE90DWoG |

To run the authentication server, which gives other apps read access to the `username` and `language` columns, just execute this:

```
docker run -d -p 8080:80 -e USER_CO=username -e PASS_CO=password -e PASSENC=bcrypt -e SCOPECO=username,language hucskfjs/ext_oauth
```

Now a client application can easily use the authentication service using these code lines:

```
<?php
try
{
    require_once('client.php');
    $data = authenticateToGetData('http://localhost:8080', 'username,language');
    print_r($data);
}
catch(Exception $x)
{
    print_r($x);
}
?>
```