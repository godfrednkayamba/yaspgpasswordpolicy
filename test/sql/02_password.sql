LOAD 'yaspgpp';
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
--password checks
--
--length must be >=2
--
SET yaspgpp.password_min_length TO 2;
DROP USER IF EXISTS aa;
CREATE USER aa WITH PASSWORD 'd';
CREATE USER aa WITH PASSWORD 'dd';
DROP USER IF EXISTS aa;

--
--min special >= 1
--
SET yaspgpp.password_min_special TO 1;
DROP USER IF EXISTS aa;
CREATE USER aa WITH PASSWORD 'aa';
CREATE USER aa WITH PASSWORD 'a$';
DROP USER IF EXISTS aa;
--
--min upper >=1
--
SET yaspgpp.password_min_upper TO 1;
DROP USER IF EXISTS "aa";
CREATE USER "aa" WITH PASSWORD 'aa$';
CREATE USER "aa" WITH PASSWORD 'aA$';
DROP USER IF EXISTS "aa";
--
--min lower >=2
--
SET yaspgpp.password_min_lower TO 1;
DROP USER IF EXISTS "aa";
CREATE USER "aa" WITH PASSWORD 'AA$';
CREATE USER "aa" WITH PASSWORD 'aA$';
DROP USER IF EXISTS "aa";
--
--must contain one of the characters 'a','b','c'
--
SET yaspgpp.password_contain TO 'a,b,c';
DROP USER IF EXISTS "aa";
CREATE USER "aa" WITH PASSWORD 'dddU$';
CREATE USER "aa" WITH PASSWORD 'ddaU$';
DROP USER IF EXISTS "aa";
--
--must not contain one of the characters 'x','z'
--
SET yaspgpp.password_not_contain TO 'x,z';
DROP USER IF EXISTS "aa";
CREATE USER "aa" WITH PASSWORD 'Ax$';
CREATE USER "aa" WITH PASSWORD 'Ab$';
DROP USER IF EXISTS "aa";
--
--passord contain username
--
SET yaspgpp.password_contain_username TO on;
DROP USER IF EXISTS "aa";
CREATE USER "aa" WITH PASSWORD 'aa$';
CREATE USER "aa" WITH PASSWORD 'Ab$';
DROP USER IF EXISTS "aa";
--
--ignore case while performing checks
--
SET yaspgpp.password_ignore_case TO on;
DROP USER IF EXISTS "aa";
CREATE USER "aa" WITH PASSWORD 'random_AA$';
DROP USER IF EXISTS "aa";
--
--min digit >=1
--
SET yaspgpp.password_min_digit TO 1;
DROP USER IF EXISTS aa;
CREATE USER aa WITH PASSWORD 'a@a';
CREATE USER aa WITH PASSWORD 'a@1';
DROP USER IF EXISTS aa;
--
--min password repeat 2
--
SET yaspgpp.password_min_repeat TO 2;
DROP USER IF EXISTS aa;
CREATE USER aa WITH PASSWORD '1a@bbb';
CREATE USER aa WITH PASSWORD '1a@a';
DROP USER IF EXISTS aa;
--
-- Check NULL password
--
CREATE USER aa WITH PASSWORD '1a@bcg';
ALTER USER aa PASSWORD NULL;
DROP USER IF EXISTS aa;
CREATE USER aa PASSWORD NULL;
DROP USER IF EXISTS aa;
--
-- Check whitlisted users
SET yaspgpp.password_min_repeat TO 2;
SET yaspgpp.whitelist = 'nocheck1,nocheck2,aaaaaaaa,bbbbbbbb,cccccccc,dddddddd,eeeeeeee,ffffffff,gggggggg';
DROP USER IF EXISTS nocheck1;
CREATE USER nocheck1 WITH PASSWORD 'aaaa';
DROP USER IF EXISTS nocheck1;
CREATE USER nocheck1;
DROP USER IF EXISTS nocheck2;
CREATE USER nocheck2 WITH PASSWORD 'aaaa';
ALTER USER nocheck2 WITH PASSWORD 'bbbb';
DROP USER IF EXISTS nocheck1;
DROP USER IF EXISTS nocheck2;


