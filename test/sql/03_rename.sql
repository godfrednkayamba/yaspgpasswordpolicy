--suppress "MD5 password cleared because of role rename" messages
SET client_min_messages TO warning;

CREATE USER aaa PASSWORD 'DummY';
CREATE USER bbb;

LOAD 'yaspgpasswordpolicy';
--
--reset all settings
--
SET yaspgpasswordpolicy.username_min_length TO DEFAULT;
SET yaspgpasswordpolicy.username_min_special TO DEFAULT;
SET yaspgpasswordpolicy.username_min_upper TO DEFAULT;
SET yaspgpasswordpolicy.username_min_upper TO DEFAULT;
SET yaspgpasswordpolicy.username_min_digit TO DEFAULT;
SET yaspgpasswordpolicy.username_contain_password TO DEFAULT;
SET yaspgpasswordpolicy.username_ignore_case TO DEFAULT;
SET yaspgpasswordpolicy.username_contain TO DEFAULT;
SET yaspgpasswordpolicy.username_not_contain TO DEFAULT;
SET yaspgpasswordpolicy.username_min_repeat TO DEFAULT;
SET yaspgpasswordpolicy.password_min_length TO DEFAULT;
SET yaspgpasswordpolicy.password_min_special TO DEFAULT;
SET yaspgpasswordpolicy.password_min_upper TO DEFAULT;
SET yaspgpasswordpolicy.password_min_upper TO DEFAULT;
SET yaspgpasswordpolicy.password_min_digit TO DEFAULT;
SET yaspgpasswordpolicy.password_contain_username TO DEFAULT;
SET yaspgpasswordpolicy.password_ignore_case TO DEFAULT;
SET yaspgpasswordpolicy.password_contain TO DEFAULT;
SET yaspgpasswordpolicy.password_not_contain TO DEFAULT;
SET yaspgpasswordpolicy.password_min_repeat TO DEFAULT;

--
--length must be >=2
--
SET yaspgpasswordpolicy.username_min_length TO 2;
ALTER USER aaa RENAME TO b;
-- Check that renaiming a user without password also invoke the extension
ALTER USER bbb RENAME TO b;
DROP USER bbb;
CREATE USER b;

--
--min user repeat
--
SET yaspgpasswordpolicy.username_min_repeat TO 5;
ALTER USER aaa RENAME TO abbbaaaaaa;
--
--min special >= 1
--
SET yaspgpasswordpolicy.username_min_special TO 1;
ALTER USER aaa RENAME TO bbb;
--
--min upper >=1
--
SET yaspgpasswordpolicy.username_min_upper TO 1;
ALTER USER aaa RENAME TO "b$bb";
--
--min lower >=2
--
SET yaspgpasswordpolicy.username_min_lower TO 1;
ALTER USER aaa RENAME TO "B$BB";
--
--must contain one of the characters 'a','b','c'
--
SET yaspgpasswordpolicy.username_contain TO 'a,b,c';
ALTER USER aaa RENAME TO "d$eF";
--
--must not contain one of the characters 'x','z'
--
SET yaspgpasswordpolicy.username_not_contain TO 'x,z';
ALTER USER aaa RENAME TO "a$exF";
--
--min digit >=1
--
SET yaspgpasswordpolicy.username_min_digit TO 1;
ALTER USER aaa RENAME TO "a$eFD";

DROP USER aaa;
