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

class Oath
{
	/**
	 * TOTP constant type descriptor for Time-based One-time Passwords
	 * 
	 * @var string
	 */
	const TOTP = 'totp';

	/**
	 * HOTP constant type descriptor for counter-based One-time Passwords
	 * 
	 * @var string
	 */
	const HOTP = 'hotp';

	/**
	 * TOTP static type descriptor for Time-based One-time Passwords
	 * 
	 * @var string
	 */
	protected static $TOTP = Oath::TOTP;

	/**
	 * HOTP static type descriptor for counter-based One-time Passwords
	 * 
	 * @var string
	 */
	protected static $HOTP = Oath::HOTP;

	/**
	 * Valid hash algorithms defined by standard.
	 * Values are:
	 * * `sha1`: hmac-sha1
	 * * `sha256`: hmac-sha256
	 * * `sha512`: hmac-sha512
	 * 
	 * @var array
	 */
	protected static $VALID_ALGORITHMS = [
		'sha1',
		'sha256',
		'sha512',
	];

	/**
	 * Valid number of digits in codes defined by standard
	 * Values are:
	 * * `6`: 6-digit codes
	 * * `8`: 8-digit codes
	 * 
	 * @var array
	 */
	protected static $VALID_DIGITS = [
		6,
		8,
	];

	/**
	 * Valid types of HMAC One-Time Passwords.
	 * Values are:
	 * * `totp`: Time-based HMAC One-Time Password
	 * * `hotp`: Counter-based HMAC One-Time Password
	 * 
	 * @var array
	 */
	protected static $VALID_TYPES = [
		Oath::TOTP,
		Oath::HOTP,
	];

	/**
	 * Default strict mode.
	 * `true` is the ultimate default.
	 * 
	 * If true, only standard values can be used.
	 *
	 * @var bool
	 */
	protected static $STRICT = true;

	/**
	 * Default type of one time password.
	 * `totp` is the ultimate default. Possible values:
	 * * `totp`: Time-based HMAC One-Time Password
	 * * `hotp`: Counter-based HMAC One-Time Password
	 *
	 * @var string
	 */
	protected static $TYPE = Oath::TOTP;

	/**
	 * Default number of digits for codes.
	 * `6` is the ultimate default. Possible values:
	 * * `6`: 6-digit codes
	 * * `8`: 8-digit codes
	 *
	 * @var integer
	 */
	protected static $DIGITS = 6;

	/**
	 * Default initial counter.
	 * `0` is the ultimate default.
	 *
	 * @var integer
	 */
	protected static $INITIAL_COUNTER = 0;

	/**
	 * Default period.
	 * `30` is the ultimate default.
	 *
	 * @var integer
	 */
	protected static $PERIOD = 30;

	/**
	 * Default length for random message generation.
	 * `50` is the ultimate default.
	 *
	 * @var int
	 */
	protected static $LENGTH = 50;

	/**
	 * Default Iterations of hashing for secret generation.
	 * `10` is the ultimate default.
	 *
	 * @var int
	 */
	protected static $ITERATIONS = 10;

	/**
	 * The issuer of otpauth
	 * No ultimate default value.
	 *
	 * @var string
	 */
	protected static $ISSUER = "";

	/**
	 * Domain name for distinction. recommended to used as account@domain combination.
	 * No ultimate default value.
	 *
	 * @var string
	 */
	protected static $DOMAIN = "";

	/**
	 * Hash algorithm which codes will be processed in.
	 * Possible values are:
	 * * `sha1`
	 * * `sha256`
	 * * `sha1`
	 * 
	 * `sha1` is the ultimate default.
	 *
	 * @var string
	 */
	protected static $ALGORITHM = "sha1";

	/**
	 * default converter class for RFC3548 base-32 conversion.
	 * It must implement `Khooz\Oath\BaseConverterInterface`.
	 * @var string
	 */
	protected static $CONVERTER = Base32::class;

	/**
	 * Converter class for RFC3548 base-32 conversion
	 * 
	 * @var BaseConverterInterface
	 */
	protected $converter;

	/**
	 * Strict mode
	 * 
	 * If true, only standard values can be used.
	 *
	 * @var bool
	 */
	protected $strict;

	/**
	 * Type of one time password.
	 * Possible values:
	 * * `totp`: Time-based HMAC One-Time Password
	 * * `hotp`: Counter-based HMAC One-Time Password
	 * 
	 * @var string 
	 */
	protected $type;

	/**
	 * Message that creates secret
	 * 
	 * @var string
	 */
	protected $message;

	/**
	 * Salt that creates secret
	 * 
	 * @var string
	 */
	protected $salt;

	/**
	 * Length for random message generation
	 * 
	 * @var int
	 */
	protected $length;

	/**
	 * Iterations of hashing for secret generation
	 * 
	 * @var int
	 */
	protected $iterations;

	/**
	 * Shared secret for HMAC
	 * 
	 * @var string
	 */
	protected $secret;

	/**
	 * The issuer of otpauth
	 * 
	 * @var string
	 */
	protected $issuer;

	/**
	 * Account name for distinction.
	 * It's recommended to be used along with the `domain` parameter.
	 * 
	 * @var string
	 */
	protected $account;

	/**
	 * Domain name for distinction.
	 * It's recommended to be used along with the `account` parameter.
	 * 
	 * @var string
	 */
	protected $domain;

	/**
	 * Hash algorithm which codes will be processed in.
	 * Possible values are:
	 * * `sha1`
	 * * `sha256`
	 * * `sha1`
	 * 
	 * @var string
	 */
	protected $algorithm;

	/**
	 * Base counter which HOTP codes are biased with.
	 * 
	 * @var string
	 */
	protected $counter;

	/**
	 * The interval of seconds which new TOTP codes are generated.
	 * 
	 * @var string
	 */
	protected $period;

	/**
	 * Nubmer of digits for a valid code.
	 * Possible values:
	 * * `6`: 6-digit codes
	 * * `8`: 8-digit codes
	 * 
	 * @var string
	 */
	protected $digits;

	/**
	 * Validates nessessary inputs for oath and returns valid or default values
	 *
	 * @param	string		$secret		Shared Secret Key
	 * @param	string		$account	Account name for identification of different keys
	 * @param	string		$domain		Domain for the account used
	 * @param	string		$issuer		Issuer of this key
	 * @param	string		$digits		Number of digits of code
	 * @param	string		$algorithm	The algorithm of code generation. Valid values are `sha1`, `sha256` and `sha1`
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
				Oath    $reference,
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
				if ($reference->strict)
				{
					$this->algorithm	= !in_array($algorithm, Oath::$VALID_ALGORITHMS)	? $reference->algorithm	: $algorithm;
					$this->digits		= !in_array($digits, Oath::$VALID_DIGITS)			? $reference->digits	: $digits;
					$this->type			= !in_array($type, Oath::$VALID_TYPES)			? $reference->type		: $type;
				}
				else
				{
					$this->algorithm	= !in_array($algorithm, hash_hmac_algos())	? $reference->algorithm	: $algorithm;
					$this->digits		= $digits;
					
				}
				$this->type			= !in_array($type, Oath::$VALID_TYPES)		?	$reference->type	: $type;
				$this->issuer     = $issuer                                 ??	$reference->issuer	?? "";
				$this->account    = $account                                ??	$reference->account	?? "";
				$this->domain     = $domain                                 ??	$reference->domain	?? "";
				$this->secret     = $secret                                 ??	$reference->secret	?? "";
				
				if ($this->type === Oath::HOTP)
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
				if ($this->type === Oath::HOTP)
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
	 * Configures the default parameters throughout the following session.
	 *
	 * @param string	$issuer				Issuer as specified in standard.
	 * @param string	$domain				Domain as specified in standard.
	 * @param integer	$period				Period for totp, must be greated than 0.
	 * @param integer	$digits				Number of digits per code as specified in standard.
	 * @param integer	$initial_counter	Initial counter for hotp, must be positive.
	 * @param integer	$length				Length of randomly generated message and salt for cryptographically secure secret generation.
	 * @param integer	$iterations			Hashing iterations for cryptographically secure secret generation.
	 * @param string	$type				Type as specified in standard, either 'hotp' or 'totp'.
	 * @param string	$algorithm			Algorithm as specified in standard, it can use all hmac algorithms available to the system if strict mode is off.
	 * @param boolean	$strict				Strict mode. If true, only values specified in the standard can be used. By default it is true.
	 * @param string	$converter			A Base32 converter class name which implements `Khooz\Oath\BaseConverterInterface`.
	 * @return void
	 */
	public static function config(
		string	$issuer				= null,
		string	$domain				= null,
		int		$period				= null,
		int		$digits				= null,
		int		$initial_counter	= null,
		int		$length				= null,
		int		$iterations			= null,
		string	$type				= null,
		string	$algorithm			= null,
		bool	$strict				= null,
		string	$converter			= null
	)
	{
		static::$STRICT				= $strict === null ? : $strict;
		static::$TYPE				= $strict ? (!in_array($type, static::$VALID_TYPES) ? : $type) : ($type === null ? : $type);
		static::$ISSUER				= $issuer === null ? : $issuer;
		static::$DOMAIN				= $domain === null ? : $domain;
		static::$PERIOD				= $period < 1 ? : $period;
		static::$INITIAL_COUNTER	= ($initial_counter === null || $initial_counter < 0) ? : $initial_counter;
		static::$ALGORITHM			= $strict ? (!in_array($algorithm, static::$VALID_ALGORITHMS) ? : $algorithm) : ($algorithm === null ? : (!in_array($algorithm, hash_hmac_algos()) ? : $algorithm));
		static::$ITERATIONS			= $iterations < 1 ? : $iterations;
		static::$LENGTH				= $length < 1 ? : $length;
		static::$DIGITS				= $strict ? (!in_array($digits, static::$VALID_DIGITS) ? : $digits) : ($digits === null ? : $digits);
		static::$CONVERTER			= $converter ? : (!in_array(BaseConverterInterface::class, class_implements($converter, true)) ? : $converter);
	}

	/**
	 * Generates a new secret
	 *
	 * @return	string	Shared secret key
	 */
	public function secret () : string
	{	
		// Making a cryptographical hash as a secret
		$message = hash_pbkdf2($this->algorithm, $this->message, $this->salt, $this->iterations, $this->length, true);

		// Base32 conversion, Use the appropriate base32 converter method here to transform secret TO base32
		return $this->converter->fromString($message);
	}

	/**
	 * Returns a URI for secret exchange.
	 *
	 * @param	string	$secret		Shared Secret Key
	 * @param	string	$account	Account name for identification of different keys
	 * @param	string	$domain		Domain for the account used
	 * @param	string	$issuer		Issuer of this key
	 * @param	int		$digits		Number of digits of code
	 * @param	string	$algorithm	The algorithm of code generation. Valid values are `sha1`, `sha256` and `sha1`
	 * @param	int		$counter	Bias for the hotp counter
	 * @param	int		$period		Interval of code generation in totp, in seconds
	 * @param	string	$type		Type of code generation. Valid values are defined constants `OATH_TOTP` and `OATH_HOTP`
	 *
	 * @return	string	Key URI
	 */
	public function getURI () : string
	{
		$valid_obj  = $this->validate(
			$this->secret,
			$this->account,
			$this->domain,
			$this->issuer,
			$this->digits,
			$this->algorithm,
			$this->counter,
			$this->period,
			$this->type
		);
		$label      = $valid_obj->getLabel();
		$parameters = http_build_query($valid_obj->getParameters(), null, null, PHP_QUERY_RFC3986);
		
		return "otpauth://{$this->type}/$label?$parameters";
	}

	/**
	 * Generates a n digit code for authentication.
	 *
	 * @param	int	$pivot	An integer that slides codes back and forth (useful to be used in slow networks)
	 * @param	int	$param	An integer, either the counter for HOTP or unix time for TOTP
	 * 
	 * @return	int	n-digit authentication code.
	 */
	public function generate (
		int	$pivot	= null,
		int $param = null
	) : int
	{
		// Preparation
		$key = $this->converter->toString($this->secret);
		if ($this->type === Oath::HOTP)
		{
			$bias = $param === null ? $this->counter : $param;
		}
		else
		{
			$bias = floor(($param === null ? microtime(true) : $param) / $this->period);
		}

		// Set bias
		$pivot = $pivot ?? 0;
		$bias += $pivot;
		$bias = $bias >= 0 ? : 0;

		// Code generation
		$message = pack('N*', 0) . pack('N*', $bias);
		$hash    = hash_hmac($this->algorithm, $message, $key, true);
		$offset  = ord($hash[19]) & 0xf;
		$otp = (
					((ord($hash[$offset + 0]) & 0x7f) << 24) |
					((ord($hash[$offset + 1]) & 0xff) << 16) |
					((ord($hash[$offset + 2]) & 0xff) << 8) |
					(ord($hash[$offset + 3]) & 0xff)
				) % pow(10, $this->digits);

		return $otp;
	}

	/**
	 * Checks if the code is valid
	 *
	 * @param	string	$secret		Shared Secret Key
	 * @param	int		$code		6 digit authentication code.
	 * @param	int		$range		An integer defining a range of codes checked away from pivot [`pivot - range`, `pivot + range`] inclusive (useful to be used in slow networks)
	 * @param	int		$pivot		An integer that slides codes back and forth (useful to be used in slow networks)
	 *
	 * @return	bool	True if succeeds, false if otherwise.
	 */
	public  function check (
		int    $code,
		int    $range     = 0,
		int    $pivot     = 0
		) : bool
	{
		// Preparation
		$checked = false;

		// Check
		if ($this->type === Oath::HOTP)
		{
			for ($i = -$range; $i <= $range; $i++)
			{
				$checked |= ($this->generate($pivot + $i) === $code);
			}
			if ($checked)
			{
				$this->counter++;
			}
		}
		else
		{
			$time = (int) microtime(true);
			for ($i = -$range; $i <= $range; $i++)
			{
				$checked |= ($this->generate($pivot + $i, $time) === $code);
			}
		}

		return $checked;
	}

	/**
	 * Default constructor
	 *
	 * @param	string	$secret				Shared secret for HMAC.
	 * @param	string	$account			Account name for distinction.
	 * @param	string	$domain				Domain name for distinction.
	 * @param	string	$issuer				The issuer of otpauth
	 * @param	string	$type				Type of one time password.
	 * @param	int		$period				The interval of seconds which new TOTP codes are generated.
	 * @param	int		$initial_counter	Initial value for counter which HOTP codes are biased with.
	 * @param	int		$digits				Nubmer of digits for a valid code.
	 * @param	string	$message			A custom message that creates secret using cryptographically secure hashing
	 * @param	string	$salt				A custom salt that creates secret using cryptographically secure hashing
	 * @param	int		$length				Length of randomly generated message and salt for cryptographically secure secret generation.
	 * @param	int		$iterations			Hashing iterations for cryptographically secure secret generation.
	 * @param	string	$algorithm			Algorithm as specified in standard, it can use all hmac algorithms available to the system if strict mode is off
	 * @param	bool	$strict				Strict mode. If true, only values specified in the standard can be used. By default it is true.
	 * @param	string	$converter			A Base32 converter class name which implements `Khooz\Oath\BaseConverterInterface`.
	 *
	 */
	public function __construct (
		string	$secret				= null,
		string	$account			= null,
		string	$domain				= null,
		string	$issuer				= null,
		string	$type				= null,
		int		$period				= null,
		int		$initial_counter	= null,
		int		$digits				= null,
		string	$message			= null,
		string	$salt				= null,
		int		$length				= null,
		int		$iterations			= null,
		string	$algorithm			= null,
		bool	$strict				= null,
		string	$converter			= null
		)
	{
		$this->strict		= $strict === null	? static::$STRICT						: $strict;
		$this->length		= $length < 1		? static::$LENGTH						: $length;
		$this->iterations	= $iterations < 1	? static::$ITERATIONS					: $iterations;
		$this->message		= empty($message)	? bin2hex(random_bytes($this->length))	: $message;
		$this->salt			= empty($salt)		? bin2hex(random_bytes($this->length))	: $salt;

		$this->issuer		= $issuer === null ? static::$ISSUER : $issuer;
		$this->domain		= $domain === null ? static::$DOMAIN : $domain;
		$this->account		= $account ?? "";

		$this->converter	= $converter	? new ${static::$CONVERTER}() : (!in_array(BaseConverterInterface::class, class_implements($converter, true)) ? new ${static::$CONVERTER}() : new $converter());
		$this->algorithm	= $strict		? (!in_array($algorithm, static::$VALID_ALGORITHMS) ? static::$ALGORITHM : $algorithm) : ($algorithm === null ? static::$ALGORITHM : (!in_array($algorithm, hash_hmac_algos()) ? static::$ALGORITHM : $algorithm));
		$this->digits		= $strict		? (!in_array($digits, static::$VALID_DIGITS) ? static::$DIGITS : $digits) : ($digits === null ? static::$DIGITS : $digits);
		$this->type			= $strict		? (!in_array($type, static::$VALID_TYPES) ? static::$TYPE : $type) : ($type === null ? static::$TYPE : $type);
		$this->secret		= $secret		?	($this->message = $this->salt = null)	: $this->secret();

		if ($this->type === Oath::HOTP)
		{ 
			$this->counter = ($initial_counter === null || $initial_counter < 0) ? static::$INITIAL_COUNTER : $initial_counter;
		}
		else
		{
			$this->period  = $period < 1 ? static::$PERIOD : $period;
		}
	}
}