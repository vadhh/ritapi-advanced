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
        description = "XSS via dangerous HTML tags combined with execution vectors"
        severity    = "medium"
        category    = "xss"
        // L-4 fix: tags alone (<svg>, <details>, <math>) are valid in CMS/rich-text.
        // Only flag when a dangerous tag appears WITH an event handler or JS source.
    strings:
        // High-risk embedding tags (flag on their own)
        $embed1 = "<iframe"    nocase
        $embed2 = "<object"    nocase
        $embed3 = "<embed"     nocase
        // Lower-risk tags — only dangerous with execution vector
        $tag4 = "<svg"       nocase
        $tag5 = "<math"      nocase
        $tag6 = "<details"   nocase
        // Execution vectors
        $exec1 = "onload"    nocase
        $exec2 = "onerror"   nocase
        $exec3 = "onmouseover" nocase
        $exec4 = "javascript:" nocase
        $exec5 = "data:text"  nocase
        $exec6 = "src="       nocase
    condition:
        // High-risk embed tag alone is sufficient
        any of ($embed1, $embed2, $embed3)
        or
        // Lower-risk tags only flagged when combined with an execution vector
        (any of ($tag4, $tag5, $tag6) and any of ($exec1, $exec2, $exec3, $exec4, $exec5, $exec6))
}
