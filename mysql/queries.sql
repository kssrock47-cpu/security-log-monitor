-- Example SQL on the monitor's MySQL copy (database seclog). Run with:
--   mysql -u root -h 127.0.0.1 seclog < mysql\queries.sql
-- or paste into any MySQL client.

-- 1. Who attacks most, and how seriously (view)
SELECT * FROM v_top_attackers ORDER BY threats DESC LIMIT 10;

-- 2. Accounts under password attack (view)
SELECT * FROM v_accounts_under_attack ORDER BY failed_logins DESC LIMIT 10;

-- 3. Threats per hour by severity, last 24 hours
SELECT hour, severity, threats FROM v_threats_per_hour
WHERE hour >= DATE_FORMAT(NOW() - INTERVAL 1 DAY, '%Y-%m-%d %H:00') ORDER BY hour, severity;

-- 4. Which MITRE ATT&CK tactics were seen, and who caught them: the AI or a known pattern (view)
SELECT * FROM v_threats_by_tactic ORDER BY threats DESC;

-- 5. Addresses that failed to log in 20+ times and then succeeded (a likely break-in)
SELECT f.src_ip, f.fails, s.first_success
FROM (SELECT src_ip, COUNT(*) AS fails, MIN(ts) AS first_fail FROM events
      WHERE outcome = 'fail' AND src_ip IS NOT NULL GROUP BY src_ip HAVING COUNT(*) >= 20) AS f
JOIN (SELECT src_ip, MIN(ts) AS first_success FROM events WHERE outcome = 'success' GROUP BY src_ip) AS s
  ON s.src_ip = f.src_ip AND s.first_success > f.first_fail
ORDER BY f.fails DESC;

-- 6. Everything one address did, threats and log lines together, in time order
SET @ip = '45.155.205.233';
SELECT first_ts AS ts, 'THREAT' AS kind, title AS what FROM alerts WHERE src_ip = @ip
UNION ALL
SELECT ts, 'log', LEFT(message, 120) FROM events WHERE src_ip = @ip
ORDER BY ts LIMIT 200;

-- 7. Log lines per connection (join with sources)
SELECT s.name, COUNT(*) AS log_lines, SUM(e.outcome = 'fail') AS failures
FROM events e JOIN sources s ON s.id = e.source_id GROUP BY s.name ORDER BY log_lines DESC;
