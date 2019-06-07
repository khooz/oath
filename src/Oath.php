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
		 * @var string Valid hash algorithms
		 */
		const ALGORITHMS = [
			'sha1',
			'sha256',
			'sha512',
		];

		/**
		 * @var string Valid number of digits in codes
		 */
		const DIGITS = [
			6,
			8,
		];

		/**
		 * @var string Valid number of digits in codes
		 */
		const TYPES = [
			'totp',
			'hotp',
		];

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
		 * @var string Message that creates secret
		 */
		public $message;

		/**
		 *
		 * @var string Salt that creates secret
		 */
		public $salt;

		/**
		 *
		 * @var string Length for random message generation
		 */
		public $length;

		/**
		 *
		 * @var string Iterations of hashing for secret generation
		 */
		public $iterations;

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
		 * @var string Hash algorithm which codes will be processed in. Valid values are `sha1`, `sha256` and `sha512`
		 */
		public $algorithm;

		/**
		 *
		 * @var string Base counter which HOTP codes are biased with.
		 */
		public $counter;

		/**
		 *
		 * @var string The interval of seconds which TOTP codes are generated.
		 */
		public $period;

		/**
		 *
		 * @var string Nubmer of digits for a valid code. Values are either `6` or `8`.
		 */
		public $digits;

		/**
		 *
		 * @var string A url linking to the oath QR code provider. It is concatenated with oath combination compatible
		 *      with Google Authenticator to generate live QR codes.
		 */
		public $qrURL;

		/**
		 * Validates nessessary inputs for oath and returns valid or default values
		 *
		 * @param	string		$secret		Shared Secret Key
		 * @param	string		$account	Account name for identification of different keys
		 * @param	string		$domain		Domain for the account used
		 * @param	string		$issuer		Issuer of this key
		 * @param	string		$digits		Number of digits of code
		 * @param	string		$algorithm	The algorithm of code generation. Valid values are `sha1`, `sha256` and `sha512`
		 * @param	string		$counter	Bias for the hotp counter
		 * @param	string		$period		Interval of code generation in totp, in seconds
		 * @param	string		$type		Type of code generation. Valid values are defined constants `OATH_TOTP` and `OATH_HOTP`
		 *
		 * @return	string						Shared secret key
		 */
		private function validate (
			string $secret    = null, 
			string $account   = null, 
			string $domain    = null, 
			string $issuer    = null, 
			int    $digits    = null,
			string $algorithm = null,
			int    $counter   = null,
			int    $period    = null,
			string $type      = null
			) : object 
		{ return new class($this, $secret, $account, $domain, $issuer, $digits, $algorithm, $counter, $period, $type)
			{
				public $type;
				public $algorithm;
				public $digits;
				public $period;
				public $counter;
				public $secret;
				public $issuer;
				public $account;
				public $domain;

				public function __construct(
					OTP    $reference,
					string $secret    = null, 
					string $account   = null, 
					string $domain    = null, 
					string $issuer    = null, 
					int    $digits    = null,
					string $algorithm = null,
					int    $counter   = null,
					int    $period    = null,
					string $type      = null
					)
				{
					$this->algorithm  = !in_array($algorithm, OTP::ALGORITHMS) ?  $reference->algorithm                           :  $algorithm;
					$this->digits     = !in_array($digits, OTP::DIGITS)        ?  $reference->digits                              :  $digits;
					$this->type       = !in_array($type, OTP::TYPES)           ?  ($type === null ? OATH_TOTP : $reference->type) :  $type;
					$this->issuer     = $issuer                                 ?? $reference->issuer                              ?? "";
					$this->account    = $account                                ?? $reference->account                             ?? "";
					$this->domain     = $domain                                 ?? $reference->domain                              ?? "";
					$this->secret     = $secret                                 ?? $reference->secret                              ?? "";
					
					if ($this->type === OATH_HOTP)
					{ 
						if (!($this->counter >= 0))
						{
							if (!($reference->counter >= 0)) 
							{
								$this->counter = 0;
							}
							else 
							{
								$this->counter = $reference->counter; 
							}
						}
					}
					else
					{
						if (!($this->period >= 1)) 
						{ 
							if (!($reference->period >= 1)) 
							{
								$this->period = 30;
							} 
							else 
							{
								$this->period = $reference->period;
							}
						}
					}
				}

				public function getLabel()
				{
					$label =  "";
					$label .= !empty($this->issuer)  ? "{$this->issuer}:" : "";
					$label .= !empty($this->account) ? "{$this->account}" : "";
					$label .= !empty($this->domain)  ? "@{$this->domain}" : "";

					return $label;
				}

				public function getParameters()
				{
					$parameters = [
						'secret'    => $this->secret,
						'algorithm' => $this->algorithm,
						'digits'    => $this->digits,
					];
					if (!empty($this->issuer)) $parameters['issuer'] = $this->issuer;
					if ($this->type === OATH_HOTP)
					{
						$parameters['counter'] = $this->counter;
					}
					else
					{
						$parameters['period'] = $this->period;
					}
				}
			};
			
		}

		/**
		 * Generates a new secret
		 *
		 * @param	string		$message		Used as secret for a hash to generate a shared secret.
		 * @param	string		$salt			Used as and IV for a hash to generate a shared secret.
		 * @param	int			$length			The length of the shared key (minus salt). Default is 50 (resulting secret of size 80).
		 * @param	int			$iterations		Iterations of the hash algorithm. Default is 10.
		 * @param	string		$algorithm		The hash algorithm. valid values are `sha1`, `sha256` and `sha512`.
		 *
		 * @return	string						Shared secret key
		 */
		public function secret (
			string $message    = null, 
			string $salt       = null,
			int    $length     = null, 
			int    $iterations = null, 
			string $algorithm  = "sha512"
			) : string
		{
			$length     = $length     < 1                         ? $this->length     : $length;
			$iterations = $iterations < 1                         ? $this->iterations : $iterations;
			$message    = empty($message)                         ? $this->message    : $message;
			$salt       = empty($salt)                            ? $this->salt       : $salt;
			$algorithm  = !in_array($algorithm, self::ALGORITHMS) ? "sha512"          : $algorithm;
			
			// Making a cryptographical hash as a secret
			$message = hash_pbkdf2($algorithm, $message, $salt, $iterations, $length, true);

			// Base32 conversion, Use the appropriate base32 converter method here to transform secret TO base32
			return $this->converter->fromString($message);
		}

		/**
		 * Returns a URI for secret exchange.
		 *
		 * @param	string		$secret		Shared Secret Key
		 * @param	string		$account	Account name for identification of different keys
		 * @param	string		$domain		Domain for the account used
		 * @param	string		$issuer		Issuer of this key
		 * @param	string		$digits		Number of digits of code
		 * @param	string		$algorithm	The algorithm of code generation. Valid values are `sha1`, `sha256` and `sha512`
		 * @param	string		$counter	Bias for the hotp counter
		 * @param	string		$period		Interval of code generation in totp, in seconds
		 * @param	string		$type		Type of code generation. Valid values are defined constants `OATH_TOTP` and `OATH_HOTP`
		 *
		 * @return	string		Key URI
		 */
		public function getURI (
			string $secret    = null, 
			string $account   = null, 
			string $domain    = null, 
			string $issuer    = null, 
			int    $digits    = null,
			string $algorithm = null,
			int    $counter   = null,
			int    $period    = null,
			string $type      = null
			) : string
		{
			$valid_obj  = $this->validate($secret, $account, $domain, $issuer, $digits, $algorithm, $counter, $period, $type);
			$label      = $valid_obj->getLabel();
			$parameters = http_build_query($valid_obj->getParameters(), null, null, PHP_QUERY_RFC3986);
			
			return "otpauth://$type/$label?$parameters";
		}

		/**
		 * Returns a live QR code.
		 *
		 * @param	string		$secret		Shared Secret Key
		 * @param	string		$account	Account name for identification of different keys
		 * @param	string		$domain		Domain for the account used
		 * @param	string		$issuer		Issuer of this key
		 * @param	string		$digits		Number of digits of code
		 * @param	string		$algorithm	The algorithm of code generation. Valid values are `sha1`, `sha256` and `sha512`
		 * @param	string		$counter	Bias for the hotp counter
		 * @param	string		$period		Interval of code generation in totp, in seconds
		 * @param	string		$type		Type of code generation. Valid values are defined constants `OATH_TOTP` and `OATH_HOTP`
		 *
		 * @return	string		URL to the live QR code generator
		 */
		public function getQRURL (
			string $secret    = null, 
			string $account   = null, 
			string $domain    = null, 
			string $issuer    = null, 
			int $digits       = null,
			string $algorithm = null,
			int $counter      = null,
			int $period       = null,
			string $type      = null
			) : string
		{

			return $this->qrURL . $this->getURI($secret, $account, $domain, $issuer, $type);
		}

		/**
		 * Generates a 6 digit code for authentication.
		 *
		 * @param	int			$n			An integer that slides codes back and forth (useful to be used in slow networks)
		 * @param	string		$secret		Shared Secret Key
		 * @param	string		$digits		Number of digits of code
		 * @param	string		$algorithm	The algorithm of code generation. Valid values are `sha1`, `sha256` and `sha512`
		 * @param	string		$counter	Bias for the hotp counter
		 * @param	string		$period		Interval of code generation in totp, in seconds
		 * @param	string		$type		Type of code generation. Valid values are defined constants `OATH_TOTP` and `OATH_HOTP`
		 *
		 * @return int 6 digit authentication code.
		 */
		public function generate (
			int    $pivot     = 0,
			string $secret    = null, 
			int    $digits    = null,
			string $algorithm = null,
			int    $counter   = null,
			int    $period    = null,
			string $type      = null
			) : int
		{
			// Preparation
			$valid_obj = $this->validate($secret, null, null, null, $digits, $algorithm, $counter, $period, $type);
			$key       = $this->converter->toString($valid_obj->secret);
			if ($valid_obj->type === OATH_HOTP)
			{
				$bias = $counter;
			}
			else
			{
				$bias = floor(microtime(true) / $valid_obj->period);
			}

			// Code generation
			$message = pack('N*', 0) . pack('N*', $bias + $pivot);
			$hash    = hash_hmac($valid_obj->algorithm, $message, $key, true);
			$offset  = ord($hash[19]) & 0xf;
			$otp = (
					   ((ord($hash[$offset + 0]) & 0x7f) << 24) |
					   ((ord($hash[$offset + 1]) & 0xff) << 16) |
					   ((ord($hash[$offset + 2]) & 0xff) << 8) |
					   (ord($hash[$offset + 3]) & 0xff)
				   ) % pow(10, $valid_obj->digits);

			return $otp;
		}

		/**
		 * Generates a 6 digit code for authentication.
		 *
		 * @param	int			$n			An integer that slides codes back and forth (useful to be used in slow networks)
		 * @param	string		$secret		Shared Secret Key
		 * @param	string		$digits		Number of digits of code
		 * @param	string		$algorithm	The algorithm of code generation. Valid values are `sha1`, `sha256` and `sha512`
		 * @param	string		$counter	Bias for the hotp counter
		 * @param	string		$period		Interval of code generation in totp, in seconds
		 * @param	string		$type		Type of code generation. Valid values are defined constants `OATH_TOTP` and `OATH_HOTP`
		 *
		 * @return int 6 digit authentication code.
		 */
		public function generate_no_validation (
			int    $pivot     = 0,
			string $secret    = null, 
			int    $digits    = null,
			string $algorithm = null,
			int    $counter   = null,
			int    $period    = null,
			string $type      = null
			) : int
		{
			// Preparation
			$key       = $this->converter->toString($secret);
			if ($type === OATH_HOTP)
			{
				$bias = $counter;
			}
			else
			{
				$bias = floor(microtime(true) / $period);
			}

			// Code generation
			$message = pack('N*', 0) . pack('N*', $bias + $pivot);
			$hash    = hash_hmac($algorithm, $message, $key, true);
			$offset  = ord($hash[19]) & 0xf;
			$otp = (
					   ((ord($hash[$offset + 0]) & 0x7f) << 24) |
					   ((ord($hash[$offset + 1]) & 0xff) << 16) |
					   ((ord($hash[$offset + 2]) & 0xff) << 8) |
					   (ord($hash[$offset + 3]) & 0xff)
				   ) % pow(10, $digits);

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
			int    $code,
			int    $range     = 0,
			int    $pivot     = 0,
			string $secret    = null, 
			int    $digits    = null,
			string $algorithm = null,
			int    $counter   = null,
			int    $period    = null,
			string $type      = null
			) : bool
		{
			// Preparation
			$valid_obj = $this->validate($secret, null, null, null, $digits, $algorithm, $counter, $period, $type);
			$checked = false;

			for ($i = -$range; $i <= $range; $i++)
			{
				$checked |= 
					$this->generate_no_validation(
						$pivot + $i, 
						$valid_obj->secret, 
						$valid_obj->digits, 
						$valid_obj->algorithm, 
						$valid_obj->counter, 
						$valid_obj->period, 
						$valid_obj->type
					) 
					=== $code;
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
			string                 $message       = null,
			string                 $salt          = null,
			int                    $length        = null, 
			int                    $iterations    = null,
			string                 $issuer        = null,
			string                 $account       = null, 
			string                 $domain        = null,
			string                 $qrURL         = null,
			BaseConverterInterface $baseConverter = null, 
			string                 $secret        = null, 
			int                    $digits        = null,
			string                 $algorithm     = null,
			int                    $counter       = null,
			int                    $period        = null,
			string                 $type          = null
			)
		{
			$this->length     = $length < 1                             ? 50                                    : $length;
			$this->iterations = $iterations < 1                         ? 10                                    : $iterations;
			$this->message    = empty($message)                         ?  bin2hex(random_bytes($this->length)) : $message;
			$this->salt       = empty($salt)                            ?  bin2hex(random_bytes($this->length)) : $salt;
			$this->algorithm  = !in_array($algorithm, self::ALGORITHMS) ?  'sha1'                               : $algorithm;
			$this->digits     = !in_array($digits, self::DIGITS)        ?  6                                    : $digits;
			$this->type       = !in_array($type, self::TYPES)           ?  OATH_TOTP                            : $type;
			$this->issuer     = $issuer                                 ?? "";
			$this->account    = $account                                ?? "";
			$this->domain     = $domain                                 ?? "";
			$this->qrURL      = $qrURL                                  ?? "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=";
			$this->converter  = $baseConverter                          ?? new Base32();
			$this->$message   = $message                                ?? "12";
			$this->$salt      = $salt                                   ?? "12";
			$this->secret     = $secret                                 ?? $this->secret($message, $salt);
			dd($this->secret);
			
			if ($this->type === OATH_HOTP)
			{ 
				$this->counter = !($counter >= 0) ? 0  : $counter;
			}
			else
			{
				$this->period  = !($period >= 1)  ? 30 : $period;
			}
		}
	}