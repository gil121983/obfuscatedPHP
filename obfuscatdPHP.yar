/*
   YARA Rule Set
   Author: Gil Stolar
   Date: 2021-01-06
   Identifier: obfuscatedPHP
   Reference: https://https://github.com/gil121983
*/

/* Rule Set ----------------------------------------------------------------- */

rule obfus_bitwise {
   meta:
      description = "Obfuscated bitwise"
      author = "Gil Stolar"
      reference = "https://https://github.com/gil121983"
      date = "2021-01-06"
   strings:
      $re1 = /\(.{1,}[\&\^\|\>{2}\<{2}]".{1,}"\)\.\(.{1,}[\&\^\|\>{2}\<{2}]".{1,}"\)\.\(.{1,}[\&\^\|\>{2}\<{2}]".{1,}"\)/ wide ascii fullword

   condition:
      all of them
}

rule suspicious_concat {
   meta:
      description = "suspicious concatenation"
      author = "Gil Stolar"
      reference = "https://https://github.com/gil121983"
      date = "2021-01-06"
   strings:
      $re1 = /(\$.{1,}\[\d\]\.){5,}/ wide ascii fullword
      $re2 = /\b.{1,}eval\(\$.{1,}\(\$.{1,}\)\)/ wide ascii
      $re3 = /\b.{1,}strto(upper|lower)\(\$.{1,}\[\d\]\).{1,}\b/ wide fullword
   condition:
      2 of them
}
