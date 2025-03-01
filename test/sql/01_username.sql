LOAD 'yaspgpasswordpolicy';
--
--reset all settings
--
SET yaspgpp.username_min_length TO DEFAULT;
SET yaspgpp.username_min_special TO DEFAULT;
SET yaspgpp.username_min_upper TO DEFAULT;
SET yaspgpp.username_min_upper TO DEFAULT;
SET yaspgpp.username_min_digit TO DEFAULT;
SET yaspgpp.username_contain_password TO DEFAULT;
SET yaspgpp.username_ignore_case TO DEFAULT;
SET yaspgpp.username_contain TO DEFAULT;
SET yaspgpp.username_not_contain TO DEFAULT;
SET yaspgpp.username_min_repeat TO DEFAULT;
SET yaspgpp.password_min_length TO DEFAULT;
SET yaspgpp.password_min_special TO DEFAULT;
SET yaspgpp.password_min_upper TO DEFAULT;
SET yaspgpp.password_min_upper TO DEFAULT;
SET yaspgpp.password_min_digit TO DEFAULT;
SET yaspgpp.password_contain_username TO DEFAULT;
SET yaspgpp.password_ignore_case TO DEFAULT;
SET yaspgpp.password_contain TO DEFAULT;
SET yaspgpp.password_not_contain TO DEFAULT;
SET yaspgpp.password_min_repeat TO DEFAULT;

--username checks
--
--length must be >=2
--
SET yaspgpp.username_min_length TO 2;
DROP USER IF EXISTS a;
CREATE USER a WITH PASSWORD 'dummy';
DROP USER IF EXISTS a;
CREATE USER a;
DROP USER IF EXISTS a;
--
--min user repeat
--
SET yaspgpp.username_min_repeat TO 5;
DROP USER IF EXISTS abbbaaaaaa;
CREATE USER abbbaaaaaa WITH PASSWORD 'dummy';
DROP USER IF EXISTS abbbaaaaaa;
--
--min special >= 1
--
SET yaspgpp.username_min_special TO 1;
DROP USER IF EXISTS a$;
CREATE USER aa WITH PASSWORD 'dummy';
CREATE USER a$ WITH PASSWORD 'dummy';
DROP USER IF EXISTS a$;
--
--min upper >=1
--
SET yaspgpp.username_min_upper TO 1;
DROP USER IF EXISTS "aA$";
CREATE USER "aa$" WITH PASSWORD 'dummy';
CREATE USER "aA$" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aA$";
--
--min lower >=2
--
SET yaspgpp.username_min_lower TO 1;
DROP USER IF EXISTS "AAA$";
CREATE USER "AAA$" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aaA$";
CREATE USER "aaA$" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aaA$";
--
--must contain one of the characters 'a','b','c'
--
SET yaspgpp.username_contain TO 'a,b,c';
DROP USER IF EXISTS "pA$user";
CREATE USER "pA$user" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aA$user";
CREATE USER "aA$user" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aA$user";
--
--must not contain one of the characters 'x','z'
--
SET yaspgpp.username_not_contain TO 'x,z';
DROP USER IF EXISTS "xaA$user";
CREATE USER "xaA$user" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aaA$user";
CREATE USER "aaA$user" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aaA$user";
--
--username contain password
--
SET yaspgpp.username_contain_password TO on;
DROP USER IF EXISTS "aaA$dummy";
CREATE USER "aaA$dummy" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aaA$usernopass";
CREATE USER "aaA$usernopass" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aaA$usernopass";
--
--ignore case while performing checks
--
SET yaspgpp.username_ignore_case TO on;
DROP USER IF EXISTS "aa$user_dummy";
CREATE USER "aa$user_dummy" WITH PASSWORD 'DUMMY';
DROP USER IF EXISTS "aa$user_DUMMY";
CREATE USER "aa$user_DUMMY" WITH PASSWORD 'dummy';
DROP USER IF EXISTS "aa$user_dummy";
--
--min digit >=1
--
SET yaspgpp.username_min_digit TO 1;
DROP USER IF EXISTS aa;
CREATE USER aa WITH PASSWORD 'dummy';
DROP USER IF EXISTS aa2;
CREATE USER aa2 WITH PASSWORD 'dummy';
DROP USER IF EXISTS aa2;

CREATE USER "a$user1" WITH PASSWORD '';
DROP USER "a$user1";
CREATE USER aa;
DROP USER aa;

