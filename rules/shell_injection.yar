/*
 * shell_injection.yar — OS command injection and shell payload YARA rules.
 */

rule ShellInjection_Operators
{
    meta:
        description = "Shell injection via command chaining operators"
        severity    = "high"
        category    = "cmdi"
    strings:
        $c1 = /;\s*(ls|cat|id|whoami|uname|pwd|env|printenv)\b/
        $c2 = /\|\s*(ls|cat|id|whoami|uname|pwd|env|printenv)\b/
        $c3 = /&&\s*(ls|cat|id|whoami|uname|pwd|env|printenv)\b/
        $c4 = /\|\|\s*(ls|cat|id|whoami|uname|pwd|env|printenv)\b/
        $c5 = /`[^`]{1,200}`/
        $c6 = /\$\([^)]{1,200}\)/
    condition:
        any of them
}

rule ShellInjection_FileRead
{
    meta:
        description = "Attempt to read sensitive system files via shell"
        severity    = "high"
        category    = "cmdi"
    strings:
        $f1 = "cat /etc/passwd"             nocase
        $f2 = "cat /etc/shadow"             nocase
        $f3 = "cat /etc/hosts"              nocase
        $f4 = "/proc/self/environ"          nocase
        $f5 = "/proc/version"               nocase
        $f6 = "cat /proc/"                  nocase
        $f7 = "type c:\\windows\\system32"  nocase
        $f8 = "type c:\\boot.ini"           nocase
    condition:
        any of them
}

rule ShellInjection_RemoteExec
{
    meta:
        description = "Remote code execution via wget/curl/nc/bash"
        severity    = "critical"
        category    = "cmdi"
    strings:
        $r1 = /\bcurl\s+-[A-Za-z]*\s+http/i
        $r2 = /\bwget\s+http/i
        $r3 = /\bnc\b.{1,50}-e\s/i
        $r4 = /\bbash\s+-[ic]/i
        $r5 = /\bsh\s+-[ic]/i
        $r6 = /python[23]?\s+-c\s+['"]/i
        $r7 = /perl\s+-e\s+['"]/i
        $r8 = "mkfifo"                      nocase
        $r9 = "/dev/tcp/"
    condition:
        any of them
}

rule ShellInjection_EnvVars
{
    meta:
        description = "Shell environment variable injection or expansion"
        severity    = "medium"
        category    = "cmdi"
    strings:
        $v1 = "${IFS}"
        $v2 = "${PATH}"
        $v3 = "$HOME"
        $v4 = "${BASH}"
        $v5 = /\$\{[A-Z_]{2,30}\}/
        $v6 = "%0a"   // newline injection
        $v7 = "%0d"   // carriage return injection
        $v8 = "%0a%0d"
    condition:
        2 of them
}

rule ShellInjection_Reverse_Shell
{
    meta:
        description = "Common reverse shell payload patterns"
        severity    = "critical"
        category    = "cmdi"
    strings:
        $rs1 = "bash -i >& /dev/tcp/"
        $rs2 = "exec 5<>/dev/tcp/"
        $rs3 = "0<&196;exec 196<>/dev/tcp/"
        $rs4 = "python -c 'import socket"
        $rs5 = "php -r '$sock=fsockopen"    nocase
        $rs6 = "ruby -rsocket -e"           nocase
        $rs7 = "/bin/sh -i"
    condition:
        any of them
}
