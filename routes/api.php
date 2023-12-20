<?php

use App\Http\Controllers\userController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
 * |--------------------------------------------------------------------------
 * | API Routes
 * |--------------------------------------------------------------------------
 * |
 * | Here is where you can register API routes for your application. These
 * | routes are loaded by the RouteServiceProvider and all of them will
 * | be assigned to the "api" middleware group. Make something great!
 * |
 */

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post('/auth/register', [userController::class, 'createUser']);
Route::post('/auth/login', [userController::class, 'loginUser']);
Route::middleware('auth:sanctum')->post('/auth/logout', [userController::class, 'logout']);
Route::get('/auth/display', [userController::class, 'Text']);
Route::middleware('auth:sanctum')->post('/auth/change/password', [userController::class, 'changePassword']);
// Route::post('/forget/password', [userController::class, 'eamilVerificaton']);
Route::post('/send/otp', [userController::class, 'sendOtp']);
Route::post('/resend/send/otp', [userController::class, 'resendOtp']);
Route::post('auth/veryfy/email', [userController::class, 'verifyEmail']);

// blog route ///

Route::middleware('auth:sanctum')->get('/auth/display/blog', [userController::class, 'showBlog']);
