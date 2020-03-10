# Oath
Oath is a One Time Password library used in authenticators. It covers both HOTP and TOTP methods of code generation.


## What is this package?
It implements the HMAC-based One-Time Password specified in [RFC6238](http://tools.ietf.org/html/rfc6238) used in many Two Step Authentication solutions. It is compatible with Authenticator Apps Like Google's and Microsoft's. It uses a @devicenull 's class called [Base32](https://github.com/devicenull/PHP-Google-Authenticator/blob/master/base32.php) for [RFC3548](https://tools.ietf.org/html/rfc3548) Base32 encodeing and decoding. Feel free to use any custom Base32-converting class, which have `encode` and `decode` public static functions.

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

## Methods
### `Oath::generate(int $pivot)`
Generates a new code based on object parameter. By using $pivot, you can go back and forth with codes and generate expired codes (negative value) or coming codes (positive value). You will get the current valid code when `$pivot = 0` (default behaviour).

```php
$oath->generate(-1); // Generates the last expired code
$oath->generate(0); // Generates the current valid code
$oath->generate(1); // Generates the next code in codes sequence
```

### `Oath::check(int $code, int $rabge, int $pivot)`
Checks an n-digit, integer `$code` with a telorance of `$range` around a `$pivot` point in codes sequence.

```php
$oath->check(123456, 0, 1); // Checks 123456 against the last expired, current, and next codes; gives user a 90s leeway in a 30s-period TOTP
```

## Properties
All non-static properties of `Oath` is accessible through it's name's `__get` and `__set` invocations; though there are some important properties and some virtual properties woth mentioning. I encourage you to see the `Oath` class in detail.

### `Oath::secret`
Along with `Oath::message` and `Oath::salt`, the secret or the other two (which make the secret if they are present) define an instance for authentication. You should exchange the secret to the user to store so you could generate the same codes sequence to compare against. You should also store either the secret, or the message & salt. The secret is a binary string represented in Base32 encoding.

#### `Oath::message` and `Oath::salt`
You either introduce a Base32 secret, or make one using a message and a salt. if you don't provide either, a randomly generated message and salt will generate a secret for you.

### `Oath->uri`
This is a virtual property which will give you an `otpauth` URL-encoded URI, so you could use a QR-code or a link to exchange authentication token instances with user.
It is formatted as bellow:
```
auth token instance = otpauth://type/label?parameters
type = hotp | totp
label = issuer:account@domain
```
The `parameters` are `secret`, `digits`, `algorithm`, `period` or `counter` in URL-encoded HTTP Query format.




# Special Thanks goes to

* phil@idontplaydarts.com for [this article](https://www.idontplaydarts.com/2011/07/google-totp-two-factor-authentication-for-php/)
* Wikipedia.org for [this article](http://en.wikipedia.org/wiki/Google_Authenticator)
* @devicenull for [this class](https://github.com/devicenull/PHP-Google-Authenticator/blob/master/base32.php)


## finally()
{
	
And if you feel like it, you can [donate here](https://paypal.me/khooz) to help me.

}