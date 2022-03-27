<?php

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\ProductController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

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

Route::controller(AuthController::class)->group(function() {
    Route::post('register', 'register');
    Route::post('login', 'login');
    Route::post('social-auth-google', 'socialAuthGoogle');
    Route::post('social-auth-facebook', 'socialAuthFacebook');
});

Route::middleware('auth:sanctum')->group( function () {

    Route::get('user', [AuthController::class, 'getUser']);
    Route::post('logout', [AuthController::class, 'logOut']);

});