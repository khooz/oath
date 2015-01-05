<?php

	/**
	 * Description of Oath
	 *
	 *  It implements the Two Step Authentication specified in RFC6238 @ http://tools.ietf.org/html/rfc6238 using OATH
	 *      and compatible with Google Authenticator App for android.
	 *  It uses a 3rd party class called Base32 for RFC3548 base 32 encode/decode. Feel free to use better adjusted
	 *      implementation.
	 *
	 *      Special Thanks goes to:
	 *          phil@idontplaydarts.com for this article https://www.idontplaydarts.com/2011/07/google-totp-two-factor-authentication-for-php/
	 *          Wikipedia.org for this article http://en.wikipedia.org/wiki/Google_Authenticator
	 *          devicenull@github.com for this class https://github.com/devicenull/PHP-Google-Authenticator/blob/master/base32.php
	 *
	 *
	 * @author Mustafa Talaeedeh Khouzani <your.brother.t@hotmail.com>
	 */

	namespace MrAudioGuy\Oath;

	defined("OATH_TOTP") ?: define("OATH_TOTP", 'totp', true);
	defined("OATH_HOTP") ?: define("OATH_HOTP", 'hotp', true);

	class Oath
	{
		/**
		 * @const string TOTP type descriptor
		 */
		const TOTP = 'totp';

		/**
		 * @const string HOTP type descriptor
		 */
		const HOTP = 'hotp';

		/**
		 *
		 * @var BaseConverterInterface Converter class for RFC3548 base 32 conversion
		 */
		protected static $converter;

		/**
		 *
		 * @var String type of one time password. 'totp' is default
		 *      totp: time-based one time password
		 *      hotp: counter-based one time password
		 */
		protected static $type;

		/**
		 *
		 * @var string Shared secret for HMAC
		 */
		public static $secret;

		/**
		 *
		 * @var string The issuer of oath QR code generator
		 */
		public static $issuer;

		/**
		 *
		 * @var string Account name for distinction. recommended to used as account@domain combination.
		 */
		public static $account;

		/**
		 *
		 * @var string Domain name for distinction. recommended to used as account@domain combination.
		 */
		public static $domain;

		/**
		 *
		 * @var string A url linking to the oath QR code provider. It is concatenated with oath combination compatible
		 *      with Google Authenticator to generate live QR codes.
		 */
		public static $qrURL;

		/**
		 * Generates a new secret
		 *
		 * @param string $message		Used as secret for a hash to generate a shared secret.
		 * @param int $length 			The length of the shared key (minus salt). Default is 50 (resulting secret of
		 *                    			size 80).
		 * @param int    $iterations	Iterations of the hash algorithm. Default is 10.
		 * @param string $algorithm		The hash algorithm.
		 *
		 * @return string				Shared secret key
		 */
		public static function secret ($message = null, $length = 50, $iterations = 10, $algorithm = "sha512")
		{
			if (empty($message))
			{
				mt_srand(microtime(true));
				$message = mt_rand();
			}
			if (empty($length))
			{
				$length = 50;
			}
			if (empty($iterations))
			{
				$iterations = 10;
			}
			if (empty($algorithm))
			{
				$algorithm = "sha512";
			}
			$message = hash_pbkdf2($algorithm, $message, $message, $iterations, $length, true);

			// Base32 conversion, Use the appropriate base32 converter method here to transform secret TO base32
			return static::$converter->fromString($message);
		}

		/**
		 * Returns a live QR code.
		 *
		 * @param string $secret Shared Secret Key
		 * @param string $account
		 * @param string $domain
		 * @param string $issuer
		 * @param string $type
		 *
		 * @return string URL to the live QR code generator
		 */
		public static function getQrUrl ($secret = null, $account = null, $domain = null, $issuer = null, $type = null)
		{
			if (empty($type))
			{
				$type = self::$type;
			}
			if (empty($issuer))
			{
				$issuer = self::$issuer;
			}
			if (empty($account))
			{
				$account = self::$account;
			}
			if (empty($domain))
			{
				$domain = self::$domain;
			}
			if (empty($secret))
			{
				$secret = "";
			}

			return static::$qrURL . "otpauth://$type/$issuer%3A$account@$domain?secret=$secret&issuer=$issuer";
		}

		/**
		 * Generates a 6 digit code for authentication.
		 *
		 * @param string $secret    Shared Secret Key
		 * @param int    $interval  The code generation interval in seconds. Default is 30.
		 * @param string $algorithm The hmac algorithm. Default is sha1.
		 *
		 * @return int 6 digit authentication code.
		 */
		public static function generate ($secret, $interval = 30, $algorithm = 'sha1')
		{
			$key     = static::$converter->toString($secret);
			$message = floor(microtime(true) / $interval);
			$message = pack('N*', 0) . pack('N*', $message);
			$hash    = hash_hmac($algorithm, $message, $key, true);
			$offset  = ord($hash[19]) & 0xf;

			$otp = (
					   ((ord($hash[$offset + 0]) & 0x7f) << 24) |
					   ((ord($hash[$offset + 1]) & 0xff) << 16) |
					   ((ord($hash[$offset + 2]) & 0xff) << 8) |
					   (ord($hash[$offset + 3]) & 0xff)
				   ) % pow(10, 6);

			return $otp;
		}

		/**
		 * Checks if the code is valid
		 *
		 * @param string $secret Shared Secret Key
		 * @param int    $code   6 digit authentication code.
		 *
		 * @return bool 		 True if succeeds, false if otherwise.
		 */
		public static function check ($secret, $code)
		{
			if (static::generate($secret) === $code)
			{
				return true;
			}

			return false;
		}

		/**
		 * Default constructor
		 *
		 * @param BaseConverterInterface $baseConverter Converter
		 * @param string                 $type			OTP type
		 * @param string                 $issuer		Issuer
		 * @param string                 $account		Account
		 * @param string                 $domain		Domain
		 * @param string                 $qrURL			Base url for qr-code generator
		 */
		public function __construct (BaseConverterInterface $baseConverter, $type = OATH_TOTP, $issuer = '',
											$account = '', $domain = '',
											$qrURL = 'https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=')
		{
			static::$converter = $baseConverter;
			static::$type      = $type;
			static::$issuer    = $issuer;
			static::$account   = $account;
			static::$domain    = $domain;
			static::$qrURL     = $qrURL;
			//static::$secret = static::$Secret();
		}
	}