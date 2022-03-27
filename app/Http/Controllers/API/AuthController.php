<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Carbon\Carbon;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
class AuthController extends Controller
{
    /**
     *  User Details
     * 
     * @return User
     */
    public function getUser()
    {
        return Auth::user();
    }

    /**
     * Register api
     *
     * @return \Illuminate\Http\Response
     */
    public function register(RegisterRequest $request)
    {
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] =  $user->createToken($request->device_name)->plainTextToken;
        $success['user'] =  $user;
   
        return $success;
    }
   
    /**
     * Login api
     *
     * @return \Illuminate\Http\Response
     */
    public function login(LoginRequest $request)
    {
        $user = User::where('email', $request->email)->first();

        if ($user && $user->provider != 'email/password') {
            throw ValidationException::withMessages([
                'sign_in' => ['Sign-in error: You used '.$user->provider.' to create this account. Please sign-in via '.$user->provider.'.'],
            ]);
        }
 
        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'sign_in' => ['The provided credentials are incorrect.'],
            ]);
        }
        $success['token'] =  $user->createToken($request->device_name)->plainTextToken;
        $success['user'] =  $user;
    
        return $success;
    }

    /**
     * Social auth google
     *
     * @return \Illuminate\Http\Response
     */
    public function socialAuthGoogle(Request $request)
    {   
        $auth = app('firebase.auth');
        
        $idTokenString = $request->firebase_token_id;

        try { 
            $verifiedIdToken = $auth->verifyIdToken($idTokenString);
        } catch (Exception $e) { 
            throw ValidationException::withMessages([
                'social_sign_in' => ['Sign-in error: Unauthorized - Token is invalid'],
            ]);  
        }

        $uid = $verifiedIdToken->claims()->get('sub');
        $userFromFirebase = $auth->getUser($uid);
        $userFromFirebase = $auth->updateUser($uid, ['emailVerified' => true]);

        $providerId = collect($userFromFirebase->providerData)->first()->providerId;
        if ($providerId == 'google.com') {
            $providerString = 'Google'; 
        }else if($providerId == 'facebook.com') {
            $providerString = 'Facebook';
        }
        
        /** check user provider */
        $validate_user = User::where('email', $userFromFirebase->email)->first();
        if ($validate_user && $validate_user->provider != $providerString) {
            throw ValidationException::withMessages([
                'social_sign_in' => ['Sign-in error: You used '.$validate_user->provider.' to create this account. Please sign-in via '.$validate_user->provider.'.'],
            ]);
        }

        $user = User::where('firebase_id', $uid)->first();

        if (!$user) {
            $userDetails = [
                'email' => $userFromFirebase->email,
                'firebase_id' => $uid,
                'provider' => $providerString,
                'password' => bcrypt($uid),
                'email_verified_at' => Carbon::now()
            ];

            if($userFromFirebase->displayName){
                $name = explode(" ",$userFromFirebase->displayName);
                $userDetails['last_name'] = array_pop($name);
                $userDetails['first_name'] = implode(" ", $name);
            }

            if($userFromFirebase->photoUrl) {
                $imageName = time().'_'.$uid.'.png';
                $userDetails["avatar"] = 'images/profiles/users/'.$imageName;
    
                if (!file_exists(storage_path('app/public/images/profiles/users/'))) {
                    mkdir(storage_path('app/public/images/profiles/users/'), 0777, true);
                }
                \Image::make($userFromFirebase->photoUrl)->save(storage_path('app/public/images/profiles/users/' .$imageName));
            }

            $user = User::create($userDetails);
        }

        return response()->json([
            'user' => $user,
            'token' => $user->createToken($request->device_name)->plainTextToken
        ]);
    }

    /**
     *  Logout api
     * 
     * @return \Illuminate\Http\Response
     */
    public function logOut(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return 'success';
    }
}
