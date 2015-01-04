<?php namespace MrAudioGuy\Oath\Facades;

use Illuminate\Support\Facades\Facade;

class Base32 extends Facade {

	/**
	 * Get the registered name of the component.
	 *
	 * @return string
	 */
	protected static function getFacadeAccessor() { return 'baseConverter'; }

}