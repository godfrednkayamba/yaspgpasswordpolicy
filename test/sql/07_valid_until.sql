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
SET yaspgpp.password_reuse_history = 0;
SET yaspgpp.password_reuse_interval = 0;

-- VALID UNTIL clause checks
SET yaspgpp.password_valid_until TO 4;
SET yaspgpp.password_valid_max TO 0;
-- fail, the VALID UNTIL clause must be present
CREATE USER aaa PASSWORD 'DummY';
-- Success, the VALID UNTIL clause is present and respect the delay
CREATE USER aaa PASSWORD 'DummY' VALID UNTIL '2050-01-01 00:00:00';
-- fail, the VALID UNTIL clause does not respect the delay
ALTER USER aaa PASSWORD 'DummY2' VALID UNTIL '2022-01-01 00:00:00';
SET yaspgpp.password_valid_max TO 180;
-- fail, the VALID UNTIL clause can not exceed a maximum of 180 days
ALTER USER aaa PASSWORD 'DummY2' VALID UNTIL '2050-01-01 00:00:00';
-- Clear the user
DROP USER aaa;
-- fail, the VALID UNTIL clause can not exceed a maximum of 180 days
CREATE USER aaa PASSWORD 'DummY2' VALID UNTIL '2050-01-01 00:00:00';
SET yaspgpp.password_valid_until to 60;
SET yaspgpp.password_reuse_interval to 15;
SET yaspgpp.password_reuse_history to 4;
CREATE role yaspgpp_test with login password 'password'; 
-- History must be empty
SELECT count(*), '0' AS "expected" FROM pg_password_history ;
