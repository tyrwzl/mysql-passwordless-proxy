# (WIP) mysql-passwordless-proxy

inspired by: https://github.com/mothership/rds-auth-proxy

## How to run

```bash
$ docker compose up -d
$ mysql -h 127.0.0.1 -u root -p -P3307

mysql> ALTER USER 'root' IDENTIFIED WITH mysql_native_password BY 'root';
Query OK, 0 rows affected (0.01 sec)

mysql> flush privileges;
Query OK, 0 rows affected (0.01 sec)

mysql> exit;
Bye

$ cargo run

$ mysql -u root -h 127.0.0.1 -P3306  --ssl-mode=DISABLED
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 20
Server version: 8.0.33 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
4 rows in set (0.01 sec)
```
