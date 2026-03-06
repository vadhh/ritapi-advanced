/*
 * credential_stuffing.yar — Credential stuffing and brute-force payload patterns.
 *
 * These rules target request bodies that contain characteristics of automated
 * credential testing tools or bulk credential lists, not individual login attempts.
 */

rule CredStuffing_Bulk_Credentials
{
    meta:
        description = "Bulk credential list — multiple user:pass pairs in one request body"
        severity    = "high"
        category    = "credential_stuffing"
    strings:
        // Multiple email:password patterns
        $cp1 = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}:[^\s"',]{4,64}/
        // Multiple lines with username:password format
        $cp2 = /[a-zA-Z0-9_\-\.]{3,32}:[^\s"',]{4,64}\n[a-zA-Z0-9_\-\.]{3,32}:/
    condition:
        #cp1 > 3 or #cp2 >= 1
}

rule CredStuffing_Tool_Signature
{
    meta:
        description = "Known credential stuffing tool artifacts in request body"
        severity    = "high"
        category    = "credential_stuffing"
    strings:
        $t1 = "credential_stuffing" nocase
        $t2 = "credentialstuffing"  nocase
        $t3 = "sentry_mba"          nocase
        $t4 = "blackbullet"         nocase
        $t5 = "openbullet"          nocase
        $t6 = "config_version"      nocase
        $t7 = "\"combo\":"          nocase
        $t8 = "\"wordlist\":"       nocase
    condition:
        any of them
}

rule CredStuffing_JSON_Array_Auth
{
    meta:
        description = "Array of credential objects sent in a single request"
        severity    = "high"
        category    = "credential_stuffing"
    strings:
        // JSON array containing multiple username/password objects
        $j1 = /\[\s*\{\s*"(username|user|email|login)"\s*:/
        $j2 = /\{\s*"(username|user|email|login)"\s*:.{1,100}"(password|passwd|pass|pwd)"\s*:/
    condition:
        // Multiple credential objects in the body
        #j2 > 2 or (#j1 >= 1 and #j2 >= 1)
}

rule CredStuffing_Common_Passwords
{
    meta:
        description = "Request body contains multiple well-known weak passwords (bulk test)"
        severity    = "medium"
        category    = "credential_stuffing"
    strings:
        $p1 = "password123"    nocase
        $p2 = "123456789"
        $p3 = "qwerty123"      nocase
        $p4 = "letmein"        nocase
        $p5 = "admin123"       nocase
        $p6 = "welcome1"       nocase
        $p7 = "iloveyou"       nocase
        $p8 = "sunshine"       nocase
        $p9 = "princess"       nocase
        $p10 = "football"      nocase
    condition:
        // Multiple common passwords in one body is a strong signal of bulk testing
        3 of them
}
