<?php namespace MrAudioGuy\Oath;

use Illuminate\Support\ServiceProvider;

class OathServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot()
	{
		$this->package('mr-audio-guy/oath');
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		//
		$this->app->booting(function()
		{
			$loader = \Illuminate\Foundation\AliasLoader::getInstance();
			$loader->alias('Oath', 'MrAudioGuy\Commons\Facades\Oath');
			$loader->alias('Base32', 'MrAudioGuy\Commons\Facades\Base32');
		});
		$this->app['baseConverter'] = $this->app->share(function($app)
		{
			return new Base32();
		});
		$this->app['oath'] = $this->app->share(function($app)
		{
			return new Oath($app['baseConverter']);
		});
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array('baseConverter','oath');
	}

}
