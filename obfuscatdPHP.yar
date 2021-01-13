/*
   YARA Rule Set
   Author: Gil Stolar
   Date: 2021-01-06
   Identifier: obfuscatedPHP
   Reference: https://github.com/gil121983/obfuscatedPHP
*/

/* Rule Set ----------------------------------------------------------------- */

rule obfus_bitwise {
   meta:
      description = "Obfuscated bitwise"
      author = "Gil Stolar"
      reference = "https://github.com/gil121983/obfuscatedPHP"
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
      reference = "https://github.com/gil121983/obfuscatedPHP"
      date = "2021-01-06"
   strings:
      $re1 = /(\$.{1,}\[\d\]\.){5,}/ wide ascii fullword
      $re2 = /\b.{1,}eval\(\$.{1,}\(\$.{1,}\)\)/ wide ascii
      $re3 = /\b.{1,}strto(upper|lower)\(\$.{1,}\[\d\]\).{1,}\b/ wide fullword
   condition:
      2 of them
}

rule suspicious_replace {
   meta:
      description = "suspicious replace"
      author = "Gil Stolar"
      reference = "https://github.com/gil121983/obfuscatedPHP"
      date = "2021-01-12"
   strings:
      $re1 = /\b.{1,}str_replace\(array.{1,}(\&\#59|\&lt|\&gt|\&\#63|\&\#34|G\&\#69|\&\#47|POST|GET|http:)*4.{1,}\b/ wide ascii fullword
   condition:
      all of them
}

rule suspicious_function_call {
   meta:
      description = "suspicious function call"
      author = "Gil Stolar"
      reference = "https://github.com/gil121983/obfuscatedPHP"
      date = "2021-01-13"
   strings:
      $re1 = /\(.{1,}\$.{1,}\=.{1,}\(.{1,}\)\)\.[^a-bA-B0-9]\$[^\=\$\(]\(.{1,}\)/ wide ascii fullword
   condition:
      all of them
}

