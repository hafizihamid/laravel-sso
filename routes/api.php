<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group(
    ['namespace' => 'Api', 'as' => 'api.', 'prefix' => 'v1'],
    function () {
        Route::get('/login', [AuthController::class, 'login']);

        // Route::post('/login', 'CustomerAuthController@login')->name('login');
        // Route::post('/register', 'CustomerAuthController@register')->name('register');

        // ------- ADMIN API ----------
        // Route::group(
        //     ['prefix' => 'admin', 'as' => 'admin.'],
        //     function () {
        //         Route::post('/login', 'AuthController@login')->name('login');
        //         Route::group(
        //             ['prefix' => 'password', 'as' => 'password.'],
        //             function () {
        //                 Route::post('/forgot', 'AuthController@forgot')->name('forgot');
        //                 Route::post('/reset', 'AuthController@reset')->name('reset');
        //                 Route::post('/set', 'UserController@setPassword')->name('set');
        //             }
        //         );
        //         Route::group(
        //             ['middleware' => ['auth:api', 'scope:admin']],
        //             function () {
        //                 Route::get('/authcheck', 'AuthController@authCheck')->name('auth-check');
        //                 Route::get('/logout', 'AuthController@logout')->name('logout');
        //             }
        //         );
        //     }
        // );
    }
);
