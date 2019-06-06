<?php

	/**
	 * class.Oath
	 * Provides a class for OATH functionalities RFC6238 {@link http://tools.ietf.org/html/rfc6238}
	 *
	 * @author Mustafa Talaeezadeh Khouzani <brother.t@live.com>
	 * @version 5.8
	 * @copyright MIT
	 *
	 * Description of Oath
	 *
	 *  It implements the Two Step Authentication specified in RFC6238 {@link http://tools.ietf.org/html/rfc6238} using OATH
	 *      and compatible with most authenricator apps like Google Authenticator and Microsoft Authenticator.
	 *  It uses a 3rd party class called Base32 for RFC3548 base32 conversion. Feel free to use better adjusted
	 *      implementation.
	 *
	 *      Special Thanks goes to:
	 *          phil@idontplaydarts.com for this article {@link https://www.idontplaydarts.com/2011/07/google-totp-two-factor-authentication-for-php/}
	 *          Wikipedia.org for this article {@link http://en.wikipedia.org/wiki/Google_Authenticator}
	 *          devicenull@github.com for this class {@link https://github.com/devicenull/PHP-Google-Authenticator/blob/master/base32.php}
	 *
	 */

	namespace Khooz\Oath;

	defined("OATH_TOTP") ?: define("OATH_TOTP", 'totp', true);
	defined("OATH_HOTP") ?: define("OATH_HOTP", 'hotp', true);

	class OTP
	{
		/**
		 * @var string TOTP Constant type descriptor for Time-based One-time Passwords
		 */
		const TOTP = 'totp';

		/**
		 * @var string HOTP Constant type descriptor for counter-based One-time Passwords
		 */
		const HOTP = 'hotp';

		/**
		 *
		 * @var BaseConverterInterface Converter class for RFC3548 base-32 conversion
		 */
		protected $converter;

		/**
		 *
		 * @var String type of one time password. 'totp' is default
		 *      totp: time-based one time password
		 *      hotp: counter-based one time password
		 */
		protected $type;

		/**
		 *
		 * @var string Shared secret for HMAC
		 */
		public $secret;

		/**
		 *
		 * @var string The issuer of oath QR code generator
		 */
		public $issuer;

		/**
		 *
		 * @var string Account name for distinction. recommended to used as account@domain combination.
		 */
		public $account;

		/**
		 *
		 * @var string Domain name for distinction. recommended to used as account@domain combination.
		 */
		public $domain;

		/**
		 *
		 * @var string A url linking to the oath QR code provider. It is concatenated with oath combination compatible
		 *      with Google Authenticator to generate live QR codes.
		 */
		public $qrURL;

		/**
		 * Generates a new secret
		 *
		 * @param	string		$message		Used as secret for a hash to generate a shared secret.
		 * @param	int			$length			The length of the shared key (minus salt). Default is 50 (resulting secret of size 80).
		 * @param	int			$iterations		Iterations of the hash algorithm. Default is 10.
		 * @param	string		$algorithm		The hash algorithm.
		 *
		 * @return	string						Shared secret key
		 */
		public  function secret (
			string $message = null, 
			int $length = 50, 
			int $iterations = 10, 
			string $algorithm = "sha512"
			) : string
		{
			if (empty($message))
			{
				$message = bin2hex(random_bytes(64));
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
			return $this->converter->fromString($message);
		}

		/**
		 * Returns a live QR code.
		 *
		 * @param	string		$secret Shared Secret Key
		 * @param	string		$account
		 * @param	string		$domain
		 * @param	string		$issuer
		 * @param	string		$type
		 *
		 * @return	string		URL to the live QR code generator
		 */
		public function getQRURL (
			string $secret = null, 
			string $account = null, 
			string $domain = null, 
			string $issuer = null, 
			string $type = null
			) : string
		{
			if (empty($type))
			{
				$type = $this->type;
			}
			if (empty($issuer))
			{
				$issuer = $this->issuer ?? "";
			}
			if (empty($account))
			{
				$account = $this->account ?? "";
			}
			if (empty($domain))
			{
				$domain = $this->domain ?? "";
			}
			if (empty($secret))
			{
				$secret = $this->secret ?? "";
			}

			return $this->qrURL . "otpauth://$type/$issuer%3A$account@$domain?secret=$secret&issuer=$issuer";
		}

		/**
		 * Generates a 6 digit code for authentication.
		 *
		 * @param	string	$secret			Shared Secret Key
		 * @param	int		$n				An integer that slides codes back and forth (useful to be used in slow networks)
		 * @param	int		$interval		The code generation interval in seconds. Default is 30.
		 * @param	string	$algorithm		The hmac algorithm. Default is sha1.
		 *
		 * @return int 6 digit authentication code.
		 */
		public function generate (
			string $secret = null, 
			int $n = 0, 
			int $interval = 30, 
			string $algorithm = 'sha1'
			) : int
		{
			$secret = $secret ?? $this->secret;
			$key     = $this->converter->toString($secret);
			$message = floor(microtime(true) / $interval) + $n;
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
		 * @param	string	$secret		Shared Secret Key
		 * @param	int		$code		6 digit authentication code.
		 * @param	int		$range		An integer defining a range from pivot `current + n` to be checked (useful to be used in slow networks)
		 * @param	int		$n			An integer that slides codes back and forth (useful to be used in slow networks)
		 *
		 * @return bool 		 True if succeeds, false if otherwise.
		 */
		public  function check (
			int $code,
			string $secret = null, 
			int $range = 0, 
			int $n = 0
			) : bool
		{
			$checked = false;
			$secret = $secret ?? $this->secret;
			for ($i = -$range; $i <= $range; $i++)
			{
				$checked |= $this->generate($secret, $n + $i) === $code;
			}

			return $checked;
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
		public function __construct (
			string $message = null,
			string $issuer = null,
			string $account = null, 
			string $domain = null,
			string $qrURL = 'https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=',
			BaseConverterInterface $baseConverter = null, 
			$type = OATH_TOTP
			)
		{
			$this->converter = $baseConverter ?? new Base32();
			$this->type      = $type;
			$this->issuer    = $issuer;
			$this->account   = $account;
			$this->domain    = $domain;
			$this->qrURL     = $qrURL;
			$this->secret = $this->secret($message);
		}
	}