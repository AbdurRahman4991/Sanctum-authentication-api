<?php

namespace App\Http\Controllers;

use App\Models\blog;
use App\Models\EmailVerification;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Auth;
use Hash;
use Validator;

class userController extends Controller
{
    public function createUser(Request $request)
    {
        try {
            // Validated
            $validateUser = Validator::make($request->all(),
                [
                    'name' => 'required',
                    'email' => 'required|email|unique:users,email',
                    'password' => 'required',
                    'accountType' => 'required',
                    // 'image' => 'required|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
                ]);
            $imageName = time() . '.' . $request->image->getClientOriginalName();
            $request->image->move(public_path('images'), $imageName);

            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'account_type' => $request->accountType,
                'avatar' => $imageName
            ]);

            $this->sendOtp($request->email);

            return response()->json([
                'status' => 'success',
                'message' => 'Register success plese veryfy yor eamil',
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function verifyEmail(Request $request)
    {
        // return 'hello';
        $email = $request->email;
        $otp = $request->otp;
        $otpData = EmailVerification::where(
            'email',
            $email,
        )->where('otp', $otp)->first();

        if ($otpData) {
            User::where('email', $email)->update([
                'is_verification' => 1
            ]);
            return response()->json([
                'status' => 'success',
                'message' => 'Varifid your account'
            ]);
        } else {
            return response()->json([
                'status' => 'false',
                'Wrong your otp'
            ]);
        }
    }

    // login section//

    public function loginUser(Request $request)
    {
        try {
            $validateUser = Validator::make($request->all(),
                [
                    'email' => 'required|email',
                    'password' => 'required'
                ]);

            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            }

            $user = User::where('email', $request->email)->first();
            if ($user == true) {
                if ($user->is_verification == 1) {
                    if (!Auth::attempt($request->only(['email', 'password']))) {
                        return response()->json([
                            'status' => false,
                            'message' => 'Email & Password does not match with our record.',
                        ], 401);
                    }

                    return response()->json([
                        'status' => true,
                        'message' => 'User Logged In Successfully',
                        'token' => $user->createToken('API TOKEN')->plainTextToken,
                        // ''user' => Auth()->user()
                    ], 200);
                } else {
                    return 'Go to verification';
                }
            } else {
                return response()->json([
                    'status' => 'false',
                    'message' => 'Invalid eamil'
                ]);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    // logout section //

    function logout()
    {
        $removeAuth = Auth()->user()->tokens()->delete();
        if ($removeAuth) {
            return response([
                'status' => true,
                'success' => 'User Logout Success'
            ], 200);
        } else {
            return response([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    public function changePassword(Request $request)
    {
        try {
            // Validated
            $validateUser = Validator::make($request->all(),
                [
                    'password' => 'required|confirmed',
                ]);

            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'validation error',
                    'errors' => $validateUser->errors()
                ], 401);
            } else {
                $logUser = Auth()->user();
                $logUser->password = Hash::make($request->password);
                $logUser->save();
                return response()->json([
                    'status' => true,
                    'message' => 'Passwrod Change Successfully',
                    // 'token' => $user->createToken("API TOKEN")->plainTextToken
                ], 200);
            }
        } catch (\Throwable $th) {
            return response()->json([
                'status' => false,
                'message' => $th->getMessage()
            ], 500);
        }
    }

    // Mail verification//
    public function sendOtp($email)
    {
        $user = $email;
        $otp = rand(100000, 999999);
        $time = time();

        EmailVerification::updateOrCreate(
            ['email' => $user],
            [
                'email' => $user,
                'otp' => $otp,
                'created_at' => $time
            ]
        );

        $data['email'] = $user;
        $data['title'] = 'Mail Verification';

        $data['body'] = 'Your OTP is:- ' . $otp;

        $sendEmailOtp = Mail::send('mailVerification', ['data' => $data], function ($message) use ($data) {
            $message->to($data['email'])->subject($data['title']);
        });
        if ($sendEmailOtp) {
            return response()->json([
                'status' => 'true',
                'success' => 'Mail send success'
            ]);
        } else {
            return response()->json([
                'status' => 'true',
                'success' => 'Mail send success'
            ]);
        }
    }

    // resending opt //

    public function resendOtp(Request $request)
    {
        $user = User::where('email', $request->email)->first();
        $otpData = EmailVerification::where('email', $request->email)->first();

        $currentTime = time();
        $time = $otpData->created_at;

        if ($currentTime >= $time && $time >= $currentTime - (90 + 5)) {  // 90 seconds
            return response()->json(['success' => false, 'msg' => 'Please try after some time']);
        } else {
            $this->sendOtp($request);  // OTP SEND
            return response()->json(['success' => true, 'msg' => 'OTP has been sent']);
        }
    }

    public function showBlog()
    {
        $authUser = Auth()->user()->account_type;
        if ($authUser == 'admin') {
            $getBlog = blog::get();
            return $getBlog;
        } else {
            return Auth()->user();
        }
    }
}
