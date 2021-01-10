/*
   YARA Rule Set
   Author: Gil Stolar 
   Date: 2021-01-06
   Identifier: HiddenGET
   Reference: https://https://github.com/gil121983
*/

/* Rule Set ----------------------------------------------------------------- */

rule scpx_phpGET {
   meta:
      description = "phpGET.php"
      author = "Gil Stolar"
      reference = "https://https://github.com/gil121983"
      date = "2021-01-06"
   strings:
      $re1 = /\(.{1,}[\&\^\|\>{2}\<{2}]".{1,}"\)\.\(.{1,}[\&\^\|\>{2}\<{2}]".{1,}"\)\.\(.{1,}[\&\^\|\>{2}\<{2}]".{1,}"\)/ wide ascii fullword
      
   condition:
      all of them
}


