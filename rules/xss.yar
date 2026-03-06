/*
 * xss.yar — Cross-Site Scripting YARA rules for HTTP request body scanning.
 */

rule XSS_Script_Tag
{
    meta:
        description = "XSS via <script> tag"
        severity    = "high"
        category    = "xss"
    strings:
        $s1 = "<script"                     nocase
        $s2 = "%3cscript"                   nocase
        $s3 = "\\u003cscript"               nocase
        $s4 = "<scr\x00ipt"                 nocase
        $s5 = "<scr%00ipt"                  nocase
    condition:
        any of them
}

rule XSS_Event_Handler
{
    meta:
        description = "XSS via HTML event handler attribute"
        severity    = "high"
        category    = "xss"
    strings:
        $e1 = /on\w{2,20}\s*=/i
        $e2 = "onerror="                    nocase
        $e3 = "onload="                     nocase
        $e4 = "onmouseover="                nocase
        $e5 = "onfocus="                    nocase
        $e6 = "onclick="                    nocase
        $e7 = "onkeydown="                  nocase
        $e8 = "onsubmit="                   nocase
    condition:
        any of them
}

rule XSS_Javascript_Protocol
{
    meta:
        description = "XSS via javascript: or vbscript: URI scheme"
        severity    = "high"
        category    = "xss"
    strings:
        $j1 = "javascript:"                 nocase
        $j2 = "javascript%3a"               nocase
        $j3 = "java\x00script:"             nocase
        $j4 = "vbscript:"                   nocase
        $j5 = "vbscript%3a"                 nocase
        $j6 = "data:text/html"              nocase
        $j7 = "data:application/javascript" nocase
    condition:
        any of them
}

rule XSS_Polyglot
{
    meta:
        description = "Common XSS polyglot payloads"
        severity    = "high"
        category    = "xss"
    strings:
        $p1 = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert()"
        $p2 = "\"><svg/onload=alert(1)>"
        $p3 = "'><img src=x onerror=alert(1)>"
        $p4 = "';alert(1)//"
        $p5 = "\";alert(1)//"
        $p6 = "alert(document.cookie)"      nocase
        $p7 = "alert(document.domain)"      nocase
        $p8 = "eval(atob("                  nocase
        $p9 = "fromCharCode("               nocase
    condition:
        any of them
}

rule XSS_Dangerous_Tags
{
    meta:
        description = "XSS via dangerous HTML tags (iframe, object, embed, svg)"
        severity    = "medium"
        category    = "xss"
    strings:
        $t1 = "<iframe"    nocase
        $t2 = "<object"    nocase
        $t3 = "<embed"     nocase
        $t4 = "<svg"       nocase
        $t5 = "<math"      nocase
        $t6 = "<details"   nocase
    condition:
        2 of them or (1 of them and any of ($t1, $t2, $t3))
}
