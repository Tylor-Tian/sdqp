CREATE TABLE IF NOT EXISTS sdqp_fixture_employees (
  employee_id STRING,
  department STRING
)
STORED AS TEXTFILE;

INSERT OVERWRITE TABLE sdqp_fixture_employees
VALUES
  ('H-100', 'warehouse'),
  ('H-200', 'ops'),
  ('H-300', 'fraud');
