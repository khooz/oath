<?php 

	/**
	 * class.Oath:Facade
	 * Provides a facade for OATH functionalities
	 *
	 * @author Mustafa Talaeezadeh Khouzani <brother.t@live.com>
	 * @version 4.2
	 * @copyright MIT
	 *
	 */

	namespace Khooz\Oath\Facades;

	use Illuminate\Support\Facades\Facade;

	class Oath extends Facade {

		/**
		 * Get the registered name of the component.
		 *
		 * @return string
		 */
		protected static function getFacadeAccessor() { return 'oath'; }

	}