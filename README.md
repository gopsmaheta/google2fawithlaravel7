# Google two factor authentication with Laravel 7 (google2fa with Laravel)

### Requirement:
dscsdcsdc
- PHP >= 7.2.5

- Laravel 7

- MySql

- PHP extention: Imagick [Install the ImageMagick for Windows user: https://mlocati.github.io/articles/php-windows-imagick.html]  



## Implementation

1. Install latest version of laravel 7 or follow the documentation [https://laravel.com/docs/7.x#installing-laravel]

	`composer create-project --prefer-dist laravel/laravel google2fawithlaravel`


2. Go to the project directory

	`cd google2fawithlaravel`

3. Install two packages for google2fa as below 

    `composer require pragmarx/google2fa-laravel`
    
    `composer require bacon/bacon-qr-code`


4. publish the ServiceProvider class which is installed under `pragmarx/google2fa-laravel` package 
    
    `php artisan vendor:publish --provider="PragmaRX\Google2FALaravel\ServiceProvider"`

5. Create Laravel auth [https://laravel.com/docs/7.x/authentication]

    - Laravel's laravel/ui package provides a quick way to scaffold all of the routes and views you need for authentication using a few simple commands: 
    `composer require laravel/ui`
    - To install Bootstrap scaffolding 
    `php artisan ui bootstrap --auth`
    
    - Please run below command to compile your fresh scaffolding.
    `npm install && npm run dev` 
    

6. Before running migration of user table (google2fawithlaravel/database/migrations/xxxxxxxx_create_users_table.php), please add two extra fields

        $table->boolean('google2fa_enable')->default(false);
	    $table->string('google2fa_secret')->nullable();

7. Run command to migrate `php artisan migrate` and make sure two extra columns are added into user table


8. Now, Let’s create necessary routes, controller method and view files to implement this functionality. Create Routes and Controller Method to Enable / Disable 2FA. Open your `web.php` file under Routes folder and add following routes into it.

    ```bash
    Route::get('/setup2fa','Auth\Google2faAuthenticationController@setup2fa')->name('2fasetup');
    Route::post('/generate2faSecret','Auth\Google2faAuthenticationController@generate2faSecret')->name('generate2faSecret');
    Route::post('/enable2fa','Auth\Google2faAuthenticationController@enable2fa')->name('enable2fa');
    Route::post('/disable2fa','Auth\Google2faAuthenticationController@disable2fa')->name('disable2fa');
    ```
9. Create controller file under auth directory `php artisan make:controller Auth/Google2faAuthenticationController` and replace code with below:
    ```bash
    <?php

    namespace App\Http\Controllers\Auth;
    
    use App\Http\Controllers\Controller;
    use Illuminate\Http\Request;
    use Illuminate\Foundation\Validation\ValidatesRequests;
    
    use Auth;
    use App\User;
    
    class Google2faAuthenticationController extends Controller
    {
        use ValidatesRequests;
    
        /**
         * Create a new authentication controller instance.
         *
         * @return void
         */
        public function __construct()
        {
            $this->middleware('web');
        }
    
        /**
         *
         * @param \Illuminate\Http\Request $request
         * @return \Illuminate\Http\Response
         */
        public function setup2fa(Request $request)
        {
            $user = Auth::user();
            $google2fa_url = "";
    
            // Check if google2fa is enabled already or not
            if(! $user->google2fa_enable) {
                $google2fa = app('pragmarx.google2fa');
                $google2fa_url = $google2fa->getQRCodeInline(
                    'Demo 2 Factor Authentication',
                    $user->email,
                    $user->google2fa_secret
                );
            }
    
            $data = [
                'user' => $user,
                'google2fa_url' => $google2fa_url
            ];
    
            return view('auth.2fasetup')->with('data', $data);
        }
    
    
        public function generate2faSecret(Request $request)
        {
    
            $user = Auth::user();
    
            // Initialise the 2FA class
            $google2fa = app('pragmarx.google2fa');
    
            // Add the secret key to the registration data
            User::where('id', $user->id)->update([
                'google2fa_enable' => 0,
                'google2fa_secret' => $google2fa->generateSecretKey(),
            ]);
    
            return redirect('/setup2fa')->with('success',"Secret Key is generated, Please verify Code to Enable 2FA");
        }
    
        public function enable2fa(Request $request)
        {
            $user = Auth::user();
            $google2fa = app('pragmarx.google2fa');
            $secret = $request->input('verify-code');
            $valid = $google2fa->verifyKey($user->google2fa_secret, $secret);
            if($valid){
                $user->google2fa_enable = 1;
                $user->save();
                return redirect('setup2fa')->with('success',"2FA is Enabled Successfully.");
            }else{
                return redirect('setup2fa')->with('error',"Invalid Verification Code, Please try again.");
            }
        }
    
        public function disable2fa(Request $request)
        {
    
            if (!(\Hash::check($request->get('current-password'), Auth::user()->password))) {
                // The passwords matches
                return redirect()->back()->with("error","Your  password does not matches with your account password. Please try again.");
            }
    
            $validatedData = $request->validate([
                'current-password' => 'required',
            ]);
            $user = Auth::user();
            $user->google2fa_enable = 0;
            $user->save();
            return redirect('/setup2fa')->with('success',"2FA is now Disabled.");
        }
    }
    ```
    
10. Create a new view file `2fasetup.blade.php` under `resources/views/auth` folder , this will handle the triggering the above controller methods.
    ``` bash
    @extends('layouts.app')
    
    @section('content')
        <div class="container">
            <div class="row">
                <div class="col-md-8 col-md-offset-2">
                    <div class="panel panel-default">
                        <div class="panel-heading"><strong>Two Factor Authentication</strong></div>
                           <div class="panel-body">
                               <p>Two factor authentication (2FA) strengthens access security by requiring two methods (also referred to as factors) to verify your identity. Two factor authentication protects against phishing, social engineering and password brute force attacks and secures your logins from attackers exploiting weak or stolen credentials.</p>
                               <br/>
                               <p>To Enable Two Factor Authentication on your Account, you need to do following steps</p>
                               <strong>
                               <ol>
                                   <li>Click on Generate Secret Button , To Generate a Unique secret QR code for your profile</li>
                                   <li>Verify the OTP from Google Authenticator Mobile App</li>
                               </ol>
                               </strong>
                               <br/>
    
                           @if (session('error'))
                                <div class="alert alert-danger">
                                    {{ session('error') }}
                                </div>
                            @endif
                            @if (session('success'))
                                <div class="alert alert-success">
                                    {{ session('success') }}
                                </div>
                            @endif
    
    
                                @if(! $data['user']->google2fa_enable && $data['user']->google2fa_secret == null)
                                   <form class="form-horizontal" method="POST" action="{{ route('generate2faSecret') }}">
                                       {{ csrf_field() }}
                                        <div class="form-group">
                                            <div class="col-md-6 col-md-offset-4">
                                                <button type="submit" class="btn btn-primary">
                                                   Generate Secret Key to Enable 2FA
                                                </button>
                                            </div>
                                        </div>
                                   </form>
                                @elseif(!$data['user']->google2fa_enable)
                                   <strong>1. Scan this barcode with your Google Authenticator App:</strong><br/>
                                   <img src="{{$data['google2fa_url'] }}" alt="">
                               <br/><br/>
                                   <strong>2.Enter the pin the code to Enable 2FA</strong><br/><br/>
                                   <form class="form-horizontal" method="POST" action="{{ route('enable2fa') }}">
                                   {{ csrf_field() }}
    
                                   <div class="form-group{{ $errors->has('verify-code') ? ' has-error' : '' }}">
                                       <label for="verify-code" class="col-md-4 control-label">Authenticator Code</label>
    
                                       <div class="col-md-6">
                                           <input id="verify-code" type="password" class="form-control" name="verify-code" required>
    
                                           @if ($errors->has('verify-code'))
                                               <span class="help-block">
                                            <strong>{{ $errors->first('verify-code') }}</strong>
                                        </span>
                                           @endif
                                       </div>
                                   </div>
                                       <div class="form-group">
                                           <div class="col-md-6 col-md-offset-4">
                                               <button type="submit" class="btn btn-primary">
                                                   Enable 2FA
                                               </button>
                                           </div>
                                       </div>
                                   </form>
                               @elseif($data['user']->google2fa_enable)
                                   <div class="alert alert-success">
                                       2FA is Currently <strong>Enabled</strong> for your account.
                                   </div>
                                   <p>If you are looking to disable Two Factor Authentication. Please confirm your password and Click Disable 2FA Button.</p>
                                   <form class="form-horizontal" method="POST" action="{{ route('disable2fa') }}">
                                   <div class="form-group{{ $errors->has('current-password') ? ' has-error' : '' }}">
                                       <label for="change-password" class="col-md-4 control-label">Current Password</label>
    
                                       <div class="col-md-6">
                                           <input id="current-password" type="password" class="form-control" name="current-password" required>
    
                                           @if ($errors->has('current-password'))
                                               <span class="help-block">
                                            <strong>{{ $errors->first('current-password') }}</strong>
                                        </span>
                                           @endif
                                       </div>
                                   </div>
                                   <div class="col-md-6 col-md-offset-5">
    
                                           {{ csrf_field() }}
                                       <button type="submit" class="btn btn-primary ">Disable 2FA</button>
                                   </div>
                                   </form>
                                @endif
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    @endsection
    
    ```
11. Since we are looking to enable Two Factor only on those accounts which has 2FA enabled in their profile, We need to extend package’s Authenticator class for that. Create a `Support` directory under `App` folder and create a new Class file `Google2FAAuthenticator.php` in it and paste below code, This class will extend the `Authenticator` class of google2fa-laravel package.
So, paste below code in `app/Support/Google2FAAuthenticator.php` file,
    ``` bash
    <?php
    
    namespace App\Support;
    
    use PragmaRX\Google2FALaravel\Support\Authenticator;
    
    class Google2FAAuthenticator extends Authenticator
    {
        protected function canPassWithoutCheckingOTP()
        {
              if(!$this->getUser()->google2fa_enable)
                  return true;
              return
                !$this->getUser()->google2fa_enable ||
                !$this->isEnabled() ||
                $this->noUserIsAuthenticated() ||
                $this->twoFactorAuthStillValid();
        }
    
        protected function getGoogle2FASecretKey()
        {
            $secret = $this->getUser()->{$this->config('otp_secret_column')};
    
            if (is_null($secret) || empty($secret)) {
                throw new InvalidSecretKey('Secret key cannot be empty.');
            }
    
            return $secret;
        }
    
    
    }
    ```
    
    #### Information: 
        - We have modified `canPassWithoutCheckingOTP` to exclude accounts which does not have 2FA Enabled. We have also modified `getGoogle2FASecretKey` to modify the location of the column where we store our secret key. 

12. Let’s create a new Middleware class `php artisan make:middleware Google2FAMiddleware` that will refer to our extended `Google2FAAuthenticator` class. Replace below code in `Google2FAMiddleware.php` file.
    
    ``` bash
    <?php
    
    namespace App\Http\Middleware;
    
    use App\Support\Google2FAAuthenticator;
    use Closure;
    
    class Google2FAMiddleware
    {
        /**
         * Handle an incoming request.
         *
         * @param  \Illuminate\Http\Request  $request
         * @param  \Closure  $next
         * @return mixed
         */
        public function handle($request, Closure $next)
        {
            $authenticator = app(Google2FAAuthenticator::class)->boot($request);
    
            if ($authenticator->isAuthenticated()) {
                return $next($request);
            }
    
            return $authenticator->makeRequestOneTimePasswordResponse();
        }
    }

    ```

13. Now, let’s register the newly created middleware in `Kernel.php`
    ```
    protected $routeMiddleware = [
        ...
        '2fa' => \App\Http\Middleware\Google2FAMiddleware::class,
    ];
    ```
    
14. Include the Middleware to Controller or Route which you want under 2FA,
    For Example modify home route: 
    ```
    Route::get('/home', 'HomeController@index')->name('home')->middleware(['auth', '2fa']);
    ```
15. Next, let’s modify the `config/google2fa.php` config file to change the view file, which will be shown to user as a two step verification.

        'view' => 'auth.google2fa',
16. Let’s go ahead and create a new view file named `google2fa.blade.php` under `views/auth` directory.

    ``` bash
    @extends('layouts.app')
    
    @section('content')
        <div class="container">
            <div class="row">
                <div class="col-md-8 col-md-offset-2">
                    <div class="panel panel-default">
                        <div class="panel-heading">Two Factor Authentication</div>
                           <div class="panel-body">
                               <p>Two factor authentication (2FA) strengthens access security by requiring two methods (also referred to as factors) to verify your identity. Two factor authentication protects against phishing, social engineering and password brute force attacks and secures your logins from attackers exploiting weak or stolen credentials.</p>
    
                           @if (session('error'))
                                <div class="alert alert-danger">
                                    {{ session('error') }}
                                </div>
                            @endif
                            @if (session('success'))
                                <div class="alert alert-success">
                                    {{ session('success') }}
                                </div>
                            @endif
    
                                   <strong>Enter the pin from Google Authenticator Enable 2FA</strong><br/><br/>
                               <form class="form-horizontal" action="{{ route('2faVerify') }}" method="POST">
                                   {{ csrf_field() }}
                                   <div class="form-group{{ $errors->has('one_time_password-code') ? ' has-error' : '' }}">
                                       <label for="one_time_password" class="col-md-4 control-label">One Time Password</label>
                                       <div class="col-md-6">
                                           <input name="one_time_password" class="form-control"  type="text"/>
                                       </div>
                                   </div>
                                   <div class="form-group">
                                       <div class="col-md-6 col-md-offset-4">
                                            <button class="btn btn-primary" type="submit">Authenticate</button>
                                       </div>
                                   </div>
                               </form>
    
                        </div>
                    </div>
                </div>
            </div>
        </div>
    @endsection

    ```

17. This view will be shown to the user just after they login successfully. They will have to enter OTP from Google Authenticator Mobile App to login into the system. We need to include the new route in our `web.php` routes file as below

    ```
    Route::post('/2faVerify', function () {
        return redirect(URL()->previous());
    })->name('2faVerify')->middleware('2fa');
    ```
    
    
18. Add a link in header to manage google2fa setting. Open `resources/views/layouts/app.blade.php` and add below code above the logout link

    ```
    <a class="dropdown-item"  href="{{ route('2fasetup') }}">
        Manage 2fa <span class="caret"></span>
    </a>
    ```


Now, at last, you are done with installation. Open browser and just hit the application URL. Register yourself and then login to enable Google Two Factor Authentication.

 















