<?php namespace MrAudioGuy\Oath\Facades;

use Illuminate\Support\Facades\Facade;

class Oath extends Facade {

	/**
	 * Get the registered name of the component.
	 *
	 * @return string
	 */
	protected static function getFacadeAccessor() { return 'oath'; }

}