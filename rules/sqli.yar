/*
 * sqli.yar — SQL Injection YARA rules for HTTP request body scanning.
 *
 * Designed for use with YARAScanner in app/utils/yara_scanner.py.
 * Targets encoded and obfuscated variants that simple regex may miss.
 */

rule SQLi_Union_Select
{
    meta:
        description = "UNION SELECT injection attempt"
        severity    = "high"
        category    = "sqli"
    strings:
        $u1 = "union select"        nocase
        $u2 = "union%20select"      nocase
        $u3 = "union+select"        nocase
        $u4 = "union/**/select"     nocase
        $u5 = "un%69on%20se%6cect"  nocase
    condition:
        any of them
}

rule SQLi_Stacked_Statement
{
    meta:
        description = "Stacked SQL statement via semicolon"
        severity    = "high"
        category    = "sqli"
    strings:
        $s1 = /;\s*(drop|delete|truncate|insert|update)\s+/i
        $s2 = /;\s*exec\s*\(/i
        $s3 = /;\s*execute\s*\(/i
        $s4 = /;\s*xp_cmdshell/i
    condition:
        any of them
}

rule SQLi_Boolean_Blind
{
    meta:
        description = "Boolean-based blind SQL injection"
        severity    = "medium"
        category    = "sqli"
    strings:
        $b1 = /'\s*or\s+'[^']+'\s*=\s*'[^']+'/i
        $b2 = /'\s*or\s+1\s*=\s*1/i
        $b3 = /'\s*or\s+true/i
        $b4 = "1=1--"
        $b5 = "1' or '1'='1"
        $b6 = "admin'--"
        $b7 = "' or 1=1#"
    condition:
        any of them
}

rule SQLi_Time_Based
{
    meta:
        description = "Time-based blind SQL injection"
        severity    = "high"
        category    = "sqli"
    strings:
        $t1 = /sleep\s*\(\s*\d+\s*\)/i
        $t2 = /waitfor\s+delay\s+'/i
        $t3 = /benchmark\s*\(\s*\d+/i
        $t4 = /pg_sleep\s*\(/i
        $t5 = /dbms_pipe\.receive_message/i
    condition:
        any of them
}

rule SQLi_Error_Based
{
    meta:
        description = "Error-based SQL injection (extractvalue, updatexml, etc.)"
        severity    = "high"
        category    = "sqli"
    strings:
        $e1 = /extractvalue\s*\(/i
        $e2 = /updatexml\s*\(/i
        $e3 = /exp\s*\(\s*~\s*\(/i
        $e4 = /floor\s*\(\s*rand\s*\(/i
        $e5 = /geometrycollection\s*\(/i
        $e6 = /polygon\s*\(\s*\(/i
    condition:
        any of them
}

rule SQLi_Information_Schema
{
    meta:
        description = "SQL injection probing information_schema or system tables"
        severity    = "high"
        category    = "sqli"
    strings:
        $i1 = "information_schema"  nocase
        $i2 = "sys.tables"          nocase
        $i3 = "sys.columns"         nocase
        $i4 = "sysobjects"          nocase
        $i5 = "syscolumns"          nocase
        $i6 = "pg_catalog"          nocase
        $i7 = "sqlite_master"       nocase
    condition:
        any of them
}
