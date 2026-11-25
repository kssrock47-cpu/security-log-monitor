# Keeping a copy in MySQL

The monitor's own working store is a single SQLite file, which needs nothing installed. It can also keep a copy of every log line and threat in a **MySQL** database. The copy has proper tables, keys and views, so the data can be queried with SQL or read by other tools such as reporting software or a SOC's database.

The monitor works the same with this switched off.

## 1. Set up MySQL (once, Windows)

From the project folder, in PowerShell:

    powershell -ExecutionPolicy Bypass -File mysql\setup-windows.ps1

This step:

* Downloads MySQL Community Server 8.4 LTS (about 270 MB) from mysql.com into `%USERPROFILE%\mysql`, and checks it against mysql.com's MD5 checksum.
* Writes `my.ini`. MySQL listens only on `127.0.0.1:3306`, with a 256 MB buffer pool.
* Creates the data folder. The `root` user has no password, which is safe only because nothing outside this PC can reach it.

No Windows service is created and no administrator rights are needed. To remove everything, delete the `mysql` folder.

For a shared or real server, create a user with a password and use it in the address: `mysql://seclog:password@host:3306/seclog`. The password is never shown on screen.

## 2. Start it

    powershell -ExecutionPolicy Bypass -File mysql\start-windows.ps1

It starts in the background in a few seconds. Stop it with `mysql\stop-windows.ps1`, which shuts it down cleanly.

## 3. Switch it on in the monitor

1. Open **Connect logs**.
2. Under **Keep a copy in MySQL**, keep the address `mysql://root@127.0.0.1:3306/seclog` and tick the switch.
3. The monitor creates the `seclog` database, the tables and the views if they don't exist.
4. It then copies every threat so far and the latest 20,000 log lines, and after that keeps copying in batches every couple of seconds.
5. The panel then shows three live reports straight from the MySQL views. Switch on **Show technical terms** to see the SQL behind each one.

You can also switch it on at start-up with `SECLOG_MYSQL=mysql://root@127.0.0.1:3306/seclog`.

## The database

| Table or view | What it holds |
|---|---|
| `sources` | One row per log connection (id, name) |
| `events` | One row per log line: `ts`, `source_id` (foreign key to `sources`), `log_format`, `host`, `app`, `src_ip`, `country`, `user_name`, `outcome` (`fail` or `success`), `message`. Indexed on time, on address and time, and on account and outcome. |
| `alerts` | One row per threat: `first_ts`, `last_ts`, `src_ip`, `country`, `caught_by` (`ai` or `pattern`), `rule_id`, `severity`, `title`, `status`, `mitre_technique`, `mitre_tactic`, `attack_step`, `times_seen`. Updated in place when its count or status changes. |
| `v_top_attackers` | Threats and serious threats per address, with first and last seen |
| `v_threats_per_hour` | Threats per hour and severity |
| `v_accounts_under_attack` | Failed logins per account, and from how many addresses |
| `v_threats_by_tactic` | Threats per MITRE ATT&CK tactic, split by AI or known pattern |

`mysql/queries.sql` has more examples. They include addresses that failed 20 or more times and then got in, and everything one address did in time order (threats and log lines together). Run them with:

    %USERPROFILE%\mysql\mysql-8.4.13.1-winx64\bin\mysql.exe -u root -h 127.0.0.1 seclog < mysql\queries.sql

All writes use `INSERT ... ON DUPLICATE KEY UPDATE`, so switching the copy off and on again never creates duplicates.

## If something goes wrong

* **"Can't reach MySQL"**: it isn't running. Run `mysql\start-windows.ps1`. The monitor keeps up to 200,000 rows waiting and copies them once MySQL is back.
* **"MySQL refused the login"**: check the user name and password in the address.
* **Port 3306 is in use**: another MySQL is running. Use it with its own address and user, or stop it first.
