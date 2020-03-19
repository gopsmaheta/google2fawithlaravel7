<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home')->middleware(['auth', '2fa']);

Route::get('/setup2fa','Auth\Google2faAuthenticationController@setup2fa')->name('2fasetup');
Route::post('/generate2faSecret','Auth\Google2faAuthenticationController@generate2faSecret')->name('generate2faSecret');
Route::post('/enable2fa','Auth\Google2faAuthenticationController@enable2fa')->name('enable2fa');
Route::post('/disable2fa','Auth\Google2faAuthenticationController@disable2fa')->name('disable2fa');

Route::post('/2faVerify', function () {
    return redirect(URL()->previous());
})->name('2faVerify')->middleware('2fa');
