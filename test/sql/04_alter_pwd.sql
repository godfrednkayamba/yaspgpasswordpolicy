CREATE USER aaa PASSWORD 'DummY';

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
--password checks
--
--length must be >=2
--
SET yaspgpasswordpolicy.password_min_length TO 2;
ALTER USER aaa PASSWORD 'd';
--
--min special >= 1
--
SET yaspgpasswordpolicy.password_min_special TO 1;
ALTER USER aaa PASSWORD 'dd';
--
--min upper >=1
--
SET yaspgpasswordpolicy.password_min_upper TO 1;
ALTER USER aaa PASSWORD 'dd$';
--
--min lower >=2
--
SET yaspgpasswordpolicy.password_min_lower TO 1;
ALTER USER aaa PASSWORD 'DD$';
--
--must contain one of the characters 'a','b','c'
--
SET yaspgpasswordpolicy.password_contain TO 'a,b,c';
ALTER USER aaa PASSWORD 'DD$d';
--
--must not contain one of the characters 'x','z'
--
SET yaspgpasswordpolicy.password_not_contain TO 'x,z';
ALTER USER aaa PASSWORD 'DD$dx';
--
-- password contain username
--
SET yaspgpasswordpolicy.password_contain_username TO on;
ALTER USER aaa PASSWORD 'DD$dxaaa';
--
--ignore case while performing checks
--
SET yaspgpasswordpolicy.password_ignore_case TO on;
ALTER USER aaa PASSWORD 'DD$dxAAA';
--
--min digit >=1
--
SET yaspgpasswordpolicy.password_min_digit TO 1;
ALTER USER aaa PASSWORD 'DD$dA';
--
--min password repeat 2
--
SET yaspgpasswordpolicy.password_min_repeat TO 2;
ALTER USER aaa PASSWORD 'DD$dccc1';

DROP USER aaa;
