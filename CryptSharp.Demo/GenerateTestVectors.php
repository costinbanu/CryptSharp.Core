#!/usr/bin/php
<?php
#region License
/*
CryptSharp
Copyright (c) 2010, 2013 James F. Bellinger <http://www.zer7.com/software/cryptsharp>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
#endregion

function bcrypt_base64_encode($bytes)
{
  return strtr(str_replace(
    '=', '', base64_encode($bytes)
    ),
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
}

function crypt_base64_encode($bytes)
{
  return strtr(str_replace(
    '=', '', base64_encode($bytes)
    ),
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');
}

function writeEntry($f, $randomPW, $crypted)
{
  $base64RandomPW = base64_encode($randomPW);
  fwrite($f, "$base64RandomPW,$crypted\r\n");
}

function writeBCryptTestVectors()
{
  $f = fopen('TestVectors-BCrypt.txt', "wb");
  for ($i = 0; $i < 100; $i ++)
  {
    $randomPW = openssl_random_pseudo_bytes($i);
    
    $saltEnding = sprintf('$%02d$%s', mt_rand(4, 8),
      bcrypt_base64_encode(openssl_random_pseudo_bytes(16)));

    foreach (array('a', 'x', 'y') as $type)
    {      
      $salt = "$2$type$saltEnding";
      $crypted = crypt($randomPW, $salt);
      writeEntry($f, $randomPW, $crypted);
    }
  }
  fclose($f);
}

function writeDESTestVectors()
{
  $f = fopen('TestVectors-DES.txt', "wb");
  for ($i = 0; $i < 250; $i ++)
  {
    for ($saltMode = 0; $saltMode <= 2; $saltMode ++)
    {
      $randomPW = openssl_random_pseudo_bytes($i);
      
      $saltBytes = openssl_random_pseudo_bytes(2);
      $salt = $saltMode == 0 ? '..' : // PHP replaces this with /.
              $saltMode == 1 ? '/.' :
              substr(crypt_base64_encode($saltBytes), 0, 2);

      $crypted = crypt($randomPW, $salt);
      writeEntry($f, $randomPW, $crypted);
    }
  }
  fclose($f);
}

function writeExtendedDESTestVectors()
{
  $f = fopen('TestVectors-ExtendedDES.txt', "wb");
  for ($i = 0; $i < 250; $i ++)
  {
    $randomPW = openssl_random_pseudo_bytes($i);
    
    do { $roundsBytes = openssl_random_pseudo_bytes(1)."\0\0"; }
    while ($roundsBytes === "\0\0\0");
    
    $rounds = crypt_base64_encode($roundsBytes);
    $salt = crypt_base64_encode(openssl_random_pseudo_bytes(3));    
    $salt = "_$rounds$salt";

    $crypted = crypt($randomPW, $salt);
    writeEntry($f, $randomPW, $crypted);
  }
  fclose($f);
}

function writeLDAPTestVectors()
{
  $f = fopen('TestVectors-LDAP.txt', "wb");
  $ldapFile = 'ldap.tmp';
  foreach (array('{CRYPT}', '{MD5}', '{SMD5}', '{SHA}', '{SSHA}') as $method)
  {
    // slappasswd won't accept zero-length.
    for ($i = 1; $i < 200; $i ++)
    {
      // slappasswd can't handle NULL bytes when using {CRYPT}.
      do
      {
        $randomPW = openssl_random_pseudo_bytes($i);
      }
      while ($method === '{CRYPT}' && strpos($randomPW, "\0") !== false);
      
      file_put_contents($ldapFile, $randomPW);
      
      $crypted = system("slappasswd -T $ldapFile -h \"$method\"");
      writeEntry($f, $randomPW, $crypted);
    }
  }
  unlink($ldapFile);
  fclose($f);
}

function writeMD5TestVectors()
{
  $f = fopen('TestVectors-MD5.txt', "wb");
  for ($i = 0; $i < 400; $i ++)
  {
    $randomPW = openssl_random_pseudo_bytes($i);
    
    $salt = sprintf('$1$%s',
      crypt_base64_encode(openssl_random_pseudo_bytes(mt_rand(1, 12))));

    $crypted = crypt($randomPW, $salt);
    writeEntry($f, $randomPW, $crypted);
  }
  fclose($f);
}

function writePHPassTestVectors()
{
  require_once 'phpass-0.3/PasswordHash.php';
  $calculator = new PasswordHash(9, TRUE);
  
  $f = fopen('TestVectors-PHPass.txt', 'wb');
  for ($i = 0; $i < 100; $i ++)
  {
    $randomPW = openssl_random_pseudo_bytes($i);
    $crypted = $calculator->HashPassword($randomPW);
    if ($i % 2 == 0) { $crypted[1] = 'H'; }
    writeEntry($f, $randomPW, $crypted);
  }
  fclose($f);
}

function writeSHATestVectors()
{
  foreach (array('5' => 'TestVectors-SHA256.txt',
                 '6' => 'TestVectors-SHA512.txt') as $method => $path)
  {
    $f = fopen($path, "wb");
    for ($i = 0; $i < 150; $i ++)
    {
      $randomPW = openssl_random_pseudo_bytes($i);
      
      $salt = sprintf('$%s$rounds=%d$%s', $method, mt_rand(1, 20000),
        crypt_base64_encode(openssl_random_pseudo_bytes(mt_rand(1, 24))));

      $crypted = crypt($randomPW, $salt);
      writeEntry($f, $randomPW, $crypted);
    }
    fclose($f);
  }
}

function writePBKDF2TestVectors()
{
  $f = fopen('TestVectors-PBKDF2.txt', 'wb');
  for ($i = 0; $i < 100; $i ++)
  {
    $randomPW = openssl_random_pseudo_bytes($i);
    $randomSalt = openssl_random_pseudo_bytes(mt_rand(0, 20));
    $randomIters = mt_rand(1, 5000);
    $crypted = hash_pbkdf2('sha256',
                           $randomPW, $randomSalt, $randomIters,
                           128, TRUE);
    $randomPW = base64_encode($randomPW);
    $randomSalt = base64_encode($randomSalt);
    $crypted = base64_encode($crypted);
    fwrite($f, "$randomPW,$randomSalt,$randomIters,$crypted\r\n");
    writeEntry($f, $randomPW, $crypted);
  }
  fclose($f);
}

writeBCryptTestVectors();
writeDESTestVectors();
writeExtendedDESTestVectors();
//writeLDAPTestVectors(); // Needs slapd.
writeMD5TestVectors();
//writePHPassTestVectors(); // Needs PHPass.
writeSHATestVectors();
//writePBKDF2TestVectors(); // Needs PHP 5.5+.
?>

