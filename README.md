# Oath
Oath is a One Time Password library mostly known as authenticators in Google's Two-Step Verification and similar products. It covers bose HOTP and TOTP based on their RFC descriptions.


## Description of Oath
It implements the Two Step Authentication specified in RFC6238 @ http://tools.ietf.org/html/rfc6238 using OATH and compatible with Google Authenticator App for android. It uses a 3rd party class called Base32 for RFC3548 base 32 encode/decode. Feel free to use better adjusted implementation.

# Getting Started
This package uses PSR-4 autoloading which eases the installation and use with major framework or any projects utilising composer. Simply use composer to install this package as your project's dependency:
```bash
composer require khooz/oath
```

## Usage
You can simply use the default parameters of this package to generate or check HMAC-based One-Time Passwords:
```php
$otp = new Oath();
$otp->secret; // The secret used for code generation in Base32; default is randomly generated SHA1 hash
$otp->account = "john_doe"; // The account name used in combination of issuer and domain for making otpauth uri
$otp->type; // Either "hotp" or "totp"; default is totp
$otp->counter; // The current value of counter for HOTP; or null if type is "totp"; default is 0
$otp->period; // The period of code mutation for TOTP; null if type is "hotp"; default is 30

$otp->generate(); // generates new code based on current parameter
$otp->check($code); // checks current code with the provided code (integer). Returns true if both are the same.
```

You can also customize the default parameters using `config` static method before instantiating the `Oath` class, or after, for the newer instantiations.
```php
Oath::config(
	$issuer, // Default issuer as specified in standard
	$domain, // Default domain as specified in standard
	$period, // Default period for totp, must be greated than 0
	$digits, // Default number of digits per code as specified in standard
	$initial_counter, // Default initial counter for hotp, must be positive
	$length, // Default length for generated messages and salts for cryptographically secure secret generation
	$iterations, // Default hash iterations for cryptographically secure secret generation
	$type, // Default type as specified in standard, either 'hotp' or 'totp'
	$algorithm, // Default algorithm as specified in standard, it can use all hmac algorithms available to the system if strict mode is off
	$qrURI, // Default issuer as specified in standard
	$strict // Default strict mode. If true, only values specified in the standard can be used. By default it is true.
);
```

One instantiated, the `Oath` object encapsulates all the data it needs for a single user and defaults can safely be changed for furthur users.


Special Thanks goes to
======================

phil@idontplaydarts.com for this article https://www.idontplaydarts.com/2011/07/google-totp-two-factor-authentication-for-php/
Wikipedia.org for this article http://en.wikipedia.org/wiki/Google_Authenticator
devicenull@github.com for this class https://github.com/devicenull/PHP-Google-Authenticator/blob/master/base32.php
