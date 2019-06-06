<?php 

	/**
	 * class.Base32:Facade
	 * Provides a facade for base conversion functionalities
	 *
	 * @author Mustafa Talaeezadeh Khouzani <brother.t@live.com>
	 * @version 4.2
	 * @copyright MIT
	 *
	 */

	namespace Khooz\Oath\Facades;

	use Illuminate\Support\Facades\Facade;

	class Base32 extends Facade {

		/**
		 * Get the registered name of the component.
		 *
		 * @return string
		 */
		protected static function getFacadeAccessor() { return 'baseConverter'; }

	}