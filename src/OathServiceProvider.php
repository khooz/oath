<?php 

	/**
	 * interface.BaseConverterInterface
	 * Provides an interface for base conversion classes
	 *
	 * @author Mustafa Talaeezadeh Khouzani <brother.t@live.com>
	 * @version 5.8
	 * @copyright MIT
	 *
	 */

	namespace Khooz\Oath;

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
			$this->package('khooz/oath');
		}

		/**
		 * Register the service provider.
		 *
		 * @return void
		 */
		public function register()
		{
		}

		/**
		 * Get the services provided by the provider.
		 *
		 * @return array
		 */
		public function provides()
		{
		}

	}
