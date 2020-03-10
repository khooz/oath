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
		static::$STRICT				= $strict === null ? static::$STRICT : $strict;
		static::$TYPE				= $strict ? (!in_array($type, static::$VALID_TYPES) ? static::$TYPE : $type) : ($type === null ? static::$TYPE : $type);
		static::$ISSUER				= $issuer === null ? static::$ISSUER : $issuer;
		static::$DOMAIN				= $domain === null ? static::$DOMAIN : $domain;
		static::$PERIOD				= $period < 1 ? static::$PERIOD : $period;
		static::$INITIAL_COUNTER	= ($initial_counter === null || $initial_counter < 0) ? static::$INITIAL_COUNTER : $initial_counter;
		static::$ALGORITHM			= $strict ? (!in_array(strtolower($algorithm), static::$VALID_ALGORITHMS) ? static::$ALGORITHM : strtolower($algorithm)) : ($algorithm === null ? static::$ALGORITHM : (!in_array(strtolower($algorithm), hash_hmac_algos()) ? static::$ALGORITHM : strtolower($algorithm)));
		static::$ITERATIONS			= $iterations < 1 ? static::$ITERATIONS : $iterations;
		static::$LENGTH				= $length < 1 ? static::$LENGTH : $length;
		static::$DIGITS				= $strict ? (!in_array($digits, static::$VALID_DIGITS) ? static::$DIGITS : $digits) : ($digits === null ? static::$DIGITS : $digits);
		static::$CONVERTER			= $converter ? static::$CONVERTER : (!in_array(BaseConverterInterface::class, class_implements($converter, true)) ? static::$CONVERTER : $converter);
	}

	/**
	 * Generates a new secret
	 *
	 * @return	string	Shared secret key
	 */
	protected function secret () : string
	{	
		// Making a cryptographical hash as a secret
		return hash_pbkdf2($this->algorithm, $this->message, $this->salt, $this->iterations, $this->length, true);
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
		$bias = $bias >= 0 ? $bias : 0;

		// Code generation
		$message = pack('N*', 0) . pack('N*', $bias);
		$hash    = hash_hmac($this->algorithm, $message, $this->secret, true);
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
		$this->strict		= $strict === null	? static::$STRICT				: $strict;
		$this->length		= $length < 1		? static::$LENGTH				: $length;
		$this->iterations	= $iterations < 1	? static::$ITERATIONS			: $iterations;
		$this->message		= empty($message)	? random_bytes($this->length)	: $message;
		$this->salt			= empty($salt)		? random_bytes($this->length)	: $salt;

		$this->issuer		= $issuer === null ? static::$ISSUER : $issuer;
		$this->domain		= $domain === null ? static::$DOMAIN : $domain;
		$this->account		= $account ?? "";

		$algorithm = $algorithm ? null : strtolower($algorithm);
		$this->converter	= $converter	? (!in_array(BaseConverterInterface::class, class_implements($converter, true)) ? new static::$CONVERTER() : new $converter()) : new static::$CONVERTER();
		$this->algorithm	= $strict		? (!in_array($algorithm, static::$VALID_ALGORITHMS) ? static::$ALGORITHM : $algorithm) : ($algorithm === null ? static::$ALGORITHM : (!in_array($algorithm, hash_hmac_algos()) ? static::$ALGORITHM : $algorithm));
		$this->digits		= $strict		? (!in_array($digits, static::$VALID_DIGITS) ? static::$DIGITS : $digits) : ($digits === null ? static::$DIGITS : $digits);
		$this->type			= $strict		? (!in_array($type, static::$VALID_TYPES) ? static::$TYPE : $type) : ($type === null ? static::$TYPE : $type);
		
		if ($secret)
		{
			$this->secret = $this->converter->decode($secret);
			$this->message = null;
			$this->salt = null;
		}
		else
		{
			$this->secret = $this->secret();
		}

		if ($this->type === Oath::HOTP)
		{ 
			$this->counter = ($initial_counter === null || $initial_counter < 0) ? static::$INITIAL_COUNTER : $initial_counter;
			$this->period = null;
		}
		else
		{
			$this->period = $period < 1 ? static::$PERIOD : $period;
			$this->counter = null;
		}
	}

	/**
	 * Magic getter
	 *
	 * @param string $name
	 * @return void
	 */
	public function __get($name)
	{
		$method = "get" . ucfirst($name);
		if (method_exists($this, $method))
		{
			return $this->$method();
		}
		else
		{
			$trace = debug_backtrace(1);
			trigger_error(
				'Undefined property via __get(): ' . $name .
				' in ' . $trace[0]['file'] .
				' on line ' . $trace[0]['line'],
				E_USER_NOTICE);
			$k = null;

			return $k;
		}
	}

	/**
	 * Magic setter
	 *
	 * @param string $name
	 * @param mixed $value
	 */
	public function __set ($name, $value)
	{
		$method = 'set' . ucfirst($name);
		if (method_exists($this, $method))
		{
			return $this->$method($value);
		}
		else
		{
			$trace = debug_backtrace(1);
			trigger_error(
				'Undefined property via __set(): ' . $name .
				' in ' . $trace[0]['file'] .
				' on line ' . $trace[0]['line'],
				E_USER_NOTICE);
			$k = null;

			return $k;
		}
	}

	// Getters

	/**
	 * Get strict mode boolean value
	 *
	 * @return boolean
	 */
	protected function getStrict () : bool
	{
		return $this->strict;
	}
	
	/**
	 * Get autogenerated message and salt length
	 *
	 * @return integer
	 */
	protected function getLength () : int
	{
		return $this->length;
	}
	
	/**
	 * Get secret generation hash iterations
	 *
	 * @return integer
	 */
	protected function getIterations () : int
	{
		return $this->iterations;
	}
	
	/**
	 * Get message
	 *
	 * @return string
	 */
	protected function getMessage () : string
	{
		return $this->message;
	}
	
	/**
	 * Get salt
	 *
	 * @return string
	 */
	protected function getSalt () : string
	{
		return $this->salt;
	}
	
	/**
	 * Get issuer
	 *
	 * @return string
	 */
	protected function getIssuer () : string
	{
		return $this->issuer;
	}
	
	/**
	 * Get domain
	 *
	 * @return string
	 */
	protected function getDomain () : string
	{
		return $this->domain;
	}
	
	/**
	 * Get account
	 *
	 * @return string
	 */
	protected function getAccount () : string
	{
		return $this->account;
	}
	
	/**
	 * Get Base32 converter object
	 *
	 * @return BaseConverterInterface
	 */
	protected function getConverter () : BaseConverterInterface
	{
		return $this->converter;
	}
	
	/**
	 * Get HMAC algorithm
	 *
	 * @return string
	 */
	protected function getAlgorithm () : string
	{
		return $this->algorithm;
	}
	
	/**
	 * Get number of digits of a code
	 *
	 * @return integer
	 */
	protected function getDigits () : int
	{
		return $this->digits;
	}
	
	/**
	 * Get OTP type
	 *
	 * @return string
	 */
	protected function getType () : string
	{
		return $this->type;
	}
	
	/**
	 * Get underlying secret in Base32
	 *
	 * @return string
	 */
	protected function getSecret () : string
	{
		return $this->converter->encode($this->secret);
	}
	
	/**
	 * Get current counter value for HOTP
	 *
	 * @return integer
	 */
	protected function getCounter () : int
	{
		return $this->counter;
	}
	
	/**
	 * Get period of code mutation for TOTP
	 *
	 * @return integer
	 */
	protected function getPeriod () : int
	{
		return $this->period;
	}

	/**
	 * Returns a URI for secret exchange.
	 *
	 * @return	string	Key URI
	 */
	public function getUri () : string
	{
		$label = !empty($this->account) ? "{$this->account}" . (!empty($this->domain)  ? "@{$this->domain}" : "") : "";
		$label = !empty($this->issuer) ? (!empty($label) ? "{$this->issuer}:$label" : "{$this->issuer}") : $label;
		$parameters = [
			'secret'    => $this->converter->encode($this->secret),
			'algorithm' => $this->algorithm,
			'digits'    => $this->digits,
		];
		if (!empty($this->issuer))
		{
			$parameters['issuer'] = $this->issuer;
		}
		if ($this->type === Oath::HOTP)
		{
			$parameters['counter'] = $this->counter;
		}
		else
		{
			$parameters['period'] = $this->period;
		}
		$parameters = http_build_query($parameters, null, null, PHP_QUERY_RFC3986);
		
		return "otpauth://{$this->type}/$label?$parameters";
	}

	// Setters

	/**
	 * Set strict mode boolean
	 *
	 * @param boolean $value
	 * 
	 * @return boolean
	 */
	protected function setStrict (bool $value) : bool
	{
		$this->strict = $value === null ? $this->strict : $value;
		return $this->strict;
	}
	
	/**
	 * Set autogenerated message and salt length
	 * 
	 * currently useless
	 *
	 * @param integer $value
	 * 
	 * @return integer
	 */
	protected function setLength (int $value) : int
	{
		$this->length = $value < 1 ? $this->length : $value;
		return $this->length;
	}
	
	/**
	 * Set autogenerated message and salt hash iterations
	 * 
	 * currently useless
	 *
	 * @param integer $value
	 * 
	 * @return integer
	 */
	protected function setIterations (int $value) : int
	{
		$this->iterations = $value < 1 ? $this->iterations : $value;
		return $this->iterations;
	}
	
	/**
	 * Set message
	 * 
	 * currently useless
	 *
	 * @param string $value
	 * 
	 * @return string
	 */
	protected function setMessage (string $value) : string
	{
		$this->message = empty($value) ? $this->message : $value;
		return $this->message;
	}
	
	/**
	 * Set salt
	 * 
	 * currently useless
	 *
	 * @param string $value
	 * 
	 * @return string
	 */
	protected function setSalt (string $value) : string
	{
		$this->salt = empty($value) ? $this->salt : $value;
		return $this->salt;
	}
	
	/**
	 * Set issuer
	 *
	 * @param string $value
	 * 
	 * @return string
	 */
	protected function setIssuer (string $value) : string
	{
		$this->issuer = $value === null ? $this->issuer : $value;
		return $this->issuer;
	}
	
	/**
	 * Set domain
	 *
	 * @param string $value
	 * 
	 * @return string
	 */
	protected function setDomain (string $value) : string
	{
		$this->domain = $value === null ? $this->domain : $value;
		return $this->domain;
	}
	
	/**
	 * Set account
	 *
	 * @param string $value
	 * 
	 * @return string
	 */
	protected function setAccount (string $value) : string
	{
		$this->account = $value ? $this->account : $value;
		return $this->account;
	}
	
	/**
	 * Set Base32 converter object
	 *
	 * @param BaseConverterInterface $value
	 * 
	 * @return BaseConverterInterface
	 */
	protected function setConverter (BaseConverterInterface $value) : BaseConverterInterface
	{
		$this->converter = $value ? $this->converter : $value;
		return $this->converter;
	}
	
	/**
	 * Set HMAC algorithm
	 *
	 * @param string $value Algorithm as specified in standard, it can use all hmac algorithms available to the system if strict mode is off.
	 * 
	 * @return string
	 */
	protected function setAlgorithm (string $value) : string
	{
		$value = $value ? null : strtolower($value);
		$this->algorithm = $this->strict ? (!in_array($value, static::$VALID_ALGORITHMS) ? $this->algorithm : $value) : ($value === null ? $this->algorithm : (!in_array($value, hash_hmac_algos()) ? $this->algorithm : $value));
		return $this->algorithm;
	}
	
	/**
	 * Set number of digits of a code
	 *
	 * @param integer $value Number of digits per code as specified in standard. It can be any Natural number if strict mode is turned off.
	 * 
	 * @return integer
	 */
	protected function setDigits (int $value) : int
	{
		$this->digits = $this->strict ? (!in_array($value, static::$VALID_DIGITS) ? $this->digits : $value) : ($value === null ? $this->digits : $value);
		return $this->digits;
	}
	
	/**
	 * Set OTP type
	 *
	 * @param string $value It can either be `totp` or `hotp`; but can be any arbitary string if strict mode is turned off, though things get weird.
	 * 
	 * !!!Custom values are never tested!!!
	 * 
	 * @return string
	 */
	protected function setType (string $value) : string
	{
		$this->type = $this->strict ? (!in_array($value, static::$VALID_TYPES) ? $this->type : $value) : ($value === null ? $this->type : $value);
		return $this->type;
	}
	
	/**
	 * Set shared secret
	 *
	 * @param string $value It MUST be a Base32 encoded string
	 * 
	 * @return string
	 */
	protected function setSecret (string $value) : string
	{
		if ($value)
		{
			$this->secret = $this->converter->decode($value);
			$this->message = null;
			$this->salt = null;
		}
		return $this->converter->encode($this->secret);
	}
	
	/**
	 * Set the current counter in HOTP
	 *
	 * @param integer $value Must be a positive integer
	 * 
	 * @return integer
	 */
	protected function setCounter (int $value) : int
	{
		if ($this->type === Oath::HOTP)
		{ 
			$this->counter = ($value === null || $value < 0) ? $this->counter : $value;
			$this->period = null;
		}
		return $this->counter;
	}
	
	/**
	 * Set the period for code mutation in TOTP
	 *
	 * @param integer $value Must be a Natural number
	 * 
	 * @return integer
	 */
	protected function setPeriod (int $value) : int
	{
		if ($this->type === Oath::TOTP)
		{
			$this->period  = $value < 1 ? $this->period : $value;
			$this->counter = null;
		}
		return $this->period;
	}

}
