-------------
obfuscatedPHP 
-------------
A fast and simple YARA rules set, Using complex regex patterns for catching obfuscated and suspicious PHP function calls combinations that are hidden as bitwise operations or string manipulations.

For example :
  <?php $_='as'.'sert';$_($_POST[5]);?>
This combination is highly common in malicious files. Using a concatenated funcion name (assert) with argument like $_POST, while containg the concatenated function name in variable ($_) makes it harder to detect. Here comes the power of regex.

Author: Gil Stolar (Secopx LTD)
