/*
   YARA — Miasma / Shai-Hulud ".github/setup.js" dropper.
   Matches the RAW (still-obfuscated) dropper. Inner markers (aes-128-gcm, getBunPath, oven-sh)
   are encoded under the Caesar/char-code layers, so they are NOT used here — we match the
   outer structure only: a large single-line file starting with eval(), built from a char-code
   array (our wave) or a Caesar self-decoder (other waves).
*/

rule Miasma_ShaiHulud_dropper_setupjs
{
    meta:
        description = "Miasma/Shai-Hulud obfuscated dropper (.github/setup.js)"
        reference   = "incident-report.md"
        severity    = "critical"

    strings:
        $eval        = "eval("
        $eval_fn     = "eval(function"               // Caesar self-decoder wave
        $caesar      = /replace\(\/\[[a-zA-Z]+\]\/[gi]+/  // Caesar alpha-shift marker (variant-tolerant)
        $fcc         = "fromCharCode"
        $charcodes   = /(\d{1,7}\s*,\s*){400}/        // long char-code array (our wave)

    condition:
        filesize > 1MB and filesize < 12MB
        and $eval in (0..32)                          // single-line eval() dropper at file start
        and ( $charcodes or $eval_fn or $caesar or $fcc )
}

/* Companion: detect the auto-run launchers (small config files) by their command. */
rule Miasma_ShaiHulud_launcher_config
{
    meta:
        description = "Miasma/Shai-Hulud auto-run launcher (AI/IDE config referencing setup.js)"
        severity    = "high"
    strings:
        $cmd = "node .github/setup.js"
    condition:
        filesize < 1MB and $cmd
}
