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