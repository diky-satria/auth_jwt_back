<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register()
    {
        User::create([
            'name' => request('name'),
            'email' => request('email'),
            'password' => bcrypt(request('password'))
        ]);

        return response()->json([
            'message' => 'success'
        ]);
    }

    public function login()
    {
        request()->validate([
            'email' => 'required',
            'password' => 'required'
        ]);

        if(!Auth::attempt(request()->only('email','password'))){
            return response()->json([
                'message' => 'invalid credential'
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = Auth::user();

        $token = $user->createToken('token')->plainTextToken;

        $cookie = cookie('jwt', $token, 60);

        return response()->json([
            'message' => 'success',
            // 'token' => $token
        ])->withCookie($cookie);

    }

    public function user()
    {
        return Auth::user();
    }

    public function logout()
    {
        $cookie = Cookie::forget('jwt');

        return response()->json([
            'message' => 'success'
        ])->withCookie($cookie);
    }
}
