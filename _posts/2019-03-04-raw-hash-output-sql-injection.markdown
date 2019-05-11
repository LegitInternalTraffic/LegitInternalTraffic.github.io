---
layout: post
title:  "SQL Injection using raw hash output"
date:   2019-03-04 08:31:22 +0100
summary: "Injecting SQL with raw hashing output"
author: "Wesley van der Lee"
tag: "Write-up"
imgsubdir: "2019-sqli-raw-hash"
categories: ctf
---
![Login Image]({{ site.baseurl }}/images/{{ page.imgsubdir }}/login.png "Login Icon")


During a CTF organized by Hacking-Lab, we were confronted with a web challenge that contained a vulnerability. The challenge was not one of the usual jeopardy challenges, but the task was part of an attack- and defense challenge. Therefore the vulnerability required to be exploited on the other participating team’s servers as well as mitigating the vulnerability on our server. This report does not describe the entire application, but focuses on a single vulnerability and the method of exploit creation.

## The objective ## 
During the attack-defense challenge, each team was given a running but vulnerable application and its source code. The code could be patched and pushed to a git server who then tasks a Jenkins server to build the application from the repository together with a flag. Our goal was to patch the code vulnerabilities and therefore defending our own flag as well as generating exploits to attack other team’s vulnerable applications to retrieve their flags. To start off, we were given one e-mail address from a valid user registered in the system: xx@yy.com.

## The Web Application ## 
The first application was a web application, dubbed Oceanic Airlines to book and buy flights, that was written in PHP. MySQL was used by PHP to store user and flight information. Looking for the vulnerability, we immediately inspected the PHP code in search for hardcoded credentials or unsanitized SQL queries. It turned out that none of the found passwords, such as the database password, was useful to log in and all inputs were properly sanitized by the mysql_real_escape_string-method. 

## The vulnerability ##
After exhaustively searching for a weak point in the application, we discovered that when logging in, the method `searchuser` is invoked. This method returns true when authentication has successfully taken place. The full specification of the method is shown below:
 
```php
function searchuser($user, $password) {
        $u = mysql_real_escape_string($user);
        $p = mysql_real_escape_string($password);
        $pw = hash('sha256', $p, true);
        $q="SELECT * FROM user where email='$u' and pw='$pw'";
        $result = mysql_query($q, $this->connection);
        $num_rows = mysql_num_rows($result);
        if($num_rows!=0) {
                $output = mysql_fetch_assoc($result);
                return true;
        } else {
                return false;
        }
}
```

As can be seen from the code snippet, both user and password variables (retrieved from the global POST variable) are sanitized with PHP’s mysql_real_escape_string function. Next a SHA-256 hash is computed over the password. The computed hash is compared to the stored hashed password value in MySQL. This method of only storing hashed passwords in the database is advised from a security perspective, such that may the database be compromised, one would not see the plain text passwords, but first need to crack the hashes.

### The naive approach ###

The POST data in the searchuser method was the only injection point to insert user defined input. Without the difficulty of the SHA-256 hash and the mysql sanitation, an injection would be possible at the email and the password and could for example look like the following statement:

```php
$q="SELECT * FROM user where email='$u' and pw='[injection]'";
```
Ideally speaking, if no password hashing is applied prior to the creation of the SQL statement, the ```[injection]``` could be replaced with `' OR '1'='1` such that the password part of the expression would also evaluate to true as presented here:

```php
$q="SELECT * FROM user where email='$u' and pw='' OR '1'='1'";
```

If we combined the password injection with the given email address of user xx, we are able to login as user xx, thus achieving our objective. However, due to the input sanitation put in place, such an injection is unfortunately not directly possible. 

### What's the boolean value for the hash parameter? ###

After input sanitation, the data is altered one more time by PHP's hash funtion. The hash function appears to be the only way to alter the input before executing the query. If we could somehow use the hash function to create a malicious payload from a genuine input, we can alter the SQL statement in the way we want. If we have a closer look at the PHP hash function, we see the following method definition: `string hash ( string $algo , string $data [, bool $raw_output = FALSE ] )`. It appears that the hash function takes in three parameters: 
1. algo: The hashing algorithm defined as a string, SHA-256 in our case.
2. data: The data to be hashed, this is the password.
3. raw_output: An optional value to specify if we want the hash result as raw binary data (when set to true) or lowercase hexits (when set to false) which is the default return type.

So, raw binary data is returned by the hash function instead of a string of hexadecimal characters. The raw binary data that is stored in the variable `$pw` can hence be any result of the hashing function. The SHA-256 hashing function returns 64 bytes. Some byte values encode to a clear text character. Byte values ranging from `0x20` to `0x7E` encode to an ASCII character as can be seen from [this list](https://www.ibm.com/support/knowledgecenter/en/ssw_aix_72/com.ibm.aix.networkcomm/conversion_table.htm). For example `0x41` is the hexadecimal encoding of the character `A`. Expanding the idea of enforcing one ASCII character in the output, there must also exist hashes whose ASCII encoding is equal to the malicious payload of an SQL injection. Since the mysql_real_escape_string function is executed before generating the injection payload, the generated malicious payload will be executed directly in the database. 

### Minimizing the payload ###

The idea of the attack is to find a legitimate password value whose raw bytes of the password's SHA-256 hash contain the characters to perform our SQL injection.
So in consecutive order, the raw bytes of the hash result need to encode to the payload `' OR '1'='1`. This naive approach to inject the SQL statement results in a payload of 11 bytes. Finding the input to which the exact set of bytes as a result of the SHA-256 hash contains our 10 bytes is too expensive and takes thousands of years to calculate on my laptop.

We can shorten our malicious payload in multiple ways:
* The spaces are not all necessarily required, such that the payload `'OR'1'='1` would suffice: 8 bytes
* The statement `'1'='1` aids to evaluate the or-clause to true. `'OR'1` would also suffice: 5 bytes
..* Other characters might also do the job, for example `OR` and `||` are equivalent in mysql
..* It turns out that any number `[1-9]` evaluates to true MySQL

Simple mathematic shows that even 5 bytes of the hash result may take days to determine the corresponding input. After playing around with MySQL statement evaluation we came to the conclusion that we are able to find a 3 byte long injection payload: `'='`. This payload evaluates the password part of the SQL statement to true in the following way:

* `SELECT * FROM user where email='xx@yy.zz' and pw='[injection]'` (The way we want to attack the website)
* `SELECT * FROM user where email='xx@yy.zz' and pw=''=''` (injecting our payload)
* `SELECT * FROM user where email='xx@yy.zz' and (pw='')=''` (mysql evaluates the first expression)
* `SELECT * FROM user where email='xx@yy.zz' and false=''` (since the password hash stored in the database is not empty, the expression before evaluates to false)
* `SELECT * FROM user where email='xx@yy.zz' and (false='')` (comparing whether false is equal to the empty string)
* `SELECT * FROM user where email='xx@yy.zz' and (true)` (specifically for mysql, the empty is equal to the false boolean)

The payload we will generate by the hash function cannot solely be the three character sequence `'='`, because the hash function returns a hash with a length of 64 bytes. Luckily for us, almost any set of bytes on both sides of the sequence will work since `pw='random1'='random2'` evaluates to `false='random2'`. Specifically for MySQL any string will be interpreted as false if the string is `0` or starts with non ASCII bytes.

### Finding the password ###

The following python script quickly loops through a number of passwords and checks if the SHA-256 hash value of the password contain our payload, since they can potentially be a password that successfully injects our payload in the SQL statement. Note that for clarity we only looped through the numbers 0 to 10 million however, we could also search for clear text passwords that contain other ASCII characters. 


```python
import hashlib
import datetime

start = datetime.datetime.now()
for i in range(10000000):
	hash = hashlib.sha256(str(i)).digest()
	if hash.find("'='") != -1:
		print "Found: %d => %s" % (i,hash)
		print (datetime.datetime.now() - start)
```
                

The following results are printed by the python script from above.

![Password Results]({{ site.baseurl }}/images/{{ page.imgsubdir }}/pw_res.png "Python Password Results")


Under 10 seconds our script identified 6 potential passwords within our search range that contain our payload in the hash result. We see that the first found password that generates a malicious payload, `1660828` could successfully be used to login to our own application. We now have a password that can be used to bypass the input sanitation phase and successfully injects the SQL query.

## Blue team tasks ##

We are now able to exploit our own vulnerable server, but so are the other teams able to potentially exploit our application. One of our objectives was to protect our version of the application by patching the source code and pushing the new code to the organization's Git server. There are multiple ways we could achieve securing the application.

1. Changing the raw_output parameter to false, such that the hash result will not be interpreted as raw bytes.
2. Perform the method `mysql_real_escape_string` on the hashing result rather than the hash input. 

Eventually we chose for the second option, which worked as expected.

## Red team tasks ##

In a normal jeopardy style CTF, logging into a general back-end server and retrieving the flag would presumably suffice to acquire the objective points. In our case, we need to exploit the other team's servers, available through an internal IP address, with our exploit password. If the other teams did not (yet) patch their code, we could steal their flag. Note that in an attack-defence CTF flags are often temporarily valid, meaning that a team could regenerate the flag. A team only recieves points for every timeslot where a valid flag has been submitted.

We wrote a python script that exploits the other team's application, by logging in with the 'malicious' password every 10 second. If a flag has been changed, we were notified and hence were able to submit the new flag as soon as possible.

