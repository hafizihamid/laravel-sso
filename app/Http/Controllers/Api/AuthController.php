<?php

namespace App\Http\Controllers\Api;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\ForgotPasswordRequest;
use App\Http\Requests\SetPasswordRequest;
use App\Http\Requests\ValidateResetTokenRequest;
use App\Services\AuthService;

class AuthController extends ApiController
{
    protected $authService;

    public function __construct()
    {
        $this->authService = new AuthService();
    }

    /**
     * @OA\Post(
     *      path="api/v1/admin/login",
     *      operationId="loginAdmin",
     *      tags={"Admin"},
     *      summary="Admin Login",
     *      description="Get access to application",
     * @OA\RequestBody(
     *      required=true,
     *      description="Pass user credentials",
     *      @OA\JsonContent(
     *         required={"email","password"},
     *       @OA\Property(property="email", type="string", format="email", example="user1@mail.com"),
     *       @OA\Property(property="password", type="string", format="password", example="PassWord12345"),
     *         ),
     *       ),
     *      @OA\Response(
     *          response=201,
     *          description="Success",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"00","data":{"user":{"id":1,"name":"hafizi","email":"hafizihamid92@gmail.com","email_verified_at":null,"created_at":"2022-07-07T07:55:04.000000Z","updated_at":"2022-07-18T08:01:54.000000Z","is_disabled":0,"blocked_until":null,"tries":0,"roles":{"Super Admin"},"permissions":{"view-users","add-users","disable-users","view-users-details","update-users","list-roles","add-roles","update-roles","delete-roles","view-role-details","list-permissions"}},"accessToken":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiNmNmMmY2MzBmMDUyMzllODk5ZjhmYjExNjk1Y2I2ZTZmM2UyYmRiMzUyZDJmNWUwOTMyMzc3MWMwZDlkNTk1YTIxYzFjYTk2OGFjOWE1MDgiLCJpYXQiOjE2NTgxOTQ2NTQuNDQxMDU5LCJuYmYiOjE2NTgxOTQ2NTQuNDQxMDYsImV4cCI6MTY4OTczMDY1NC40MzM1OCwic3ViIjoiMSIsInNjb3BlcyI6WyJhZG1pbiJdfQ.gKInINcAXGoABlvR2q4cRHRUSXrKscHImTPzcveEOxhX_zlHM7ALM28m8D9s1NJOwiPKZKA1PteVrM6W3R_4OAxNbVUyU1oMvnrWgmF_lZGdGgnE_nVAEeic_3AZZ3RIE5SfDWhU35cktNowd08HdhmBo_QepMLbGT_U-WY9TAgghiE7GmegV92d3_whLbeLjj1lbjcf5dgtKivb7eEmdXM4uIRQwWJfuY1RHhAZON9eWmjve46pN049U9KIhAmPEfdWo5tBxRBY89AHf5M1TzDT2J1PBCvvl0bDLP0rcRpX5XIhciVtXne-1N0TI4VYzi4Lj8_3MUkPUKg1CmJwJObRxz3tTiRqAp0nelLcCbF3pVkjDyBTT6JJl8Q_nYTnE-Zkd0A87Guyd8DgOTI9YC6pl_r1samT3eA0wucAIcCCJoYqz9gbckSjoq-uAOmwCigTe_cJoEj02e1aSFpDieY3F-kwqCkGuJfgktWvq3XUWYtZFGCTV8Z0M9C64RgWuyiIHVRq44uKGupgvPUtC00O_-EuB3irwdotKk8RlLdeZ90RC05N2JRQxOH6mssNsApmNTp_reC2d6vfVQeg_WFn-wBTvMUsvWabDauplXW9_NYU7nmkj-81Hw5lGoRHdJwIXD0ruVUIaE6CimYayAMswanudgs6ujy-BUhPZ9A"}},
     *          )
     *       ),
     *      @OA\Response(
     *          response=401,
     *          description="Unauthorized",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"23","errors":{"Invalid login credentials! Please try again"}},
     *          )
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Entity",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"21","detail":"Validation Failed!","field":{"email":"The email field is required.","password":"The password field is required."}},
     *          )
     *      ),
     * )
     */

    public function login(LoginRequest $request)
    {
        $data = $this->authService->login($request);

        if ($data['status'] != config('staticdata.status_codes.ok')) {
            return $this->formatErrorResponse(
                [$data['message']],
                $data['status'],
                $data['http_code']
            );
        }

        return $this->formatDataResponse(
            $data['message'],
            $data['status'],
            $data['http_code']
        );
    }

    /**
     * @OA\Post(
     *      path="api/v1/admin/password/forgot",
     *      operationId="forgotPasswordAdmin",
     *      tags={"Admin"},
     *      summary="Admin Forgot Password",
     *      description="To unlock and retrieve account",
     *      @OA\RequestBody(
     *      required=true,
     *      description="To unlock and retrieve account",
     *      @OA\JsonContent(
     *         required={"email"},
     *       @OA\Property(property="email", type="string", format="email", example="user1@mail.com"),
     *         ),
     *       ),
     *      @OA\Response(
     *          response=201,
     *          description="Success",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"00","message":"Password reset email sent successfully."},
     *          )
     *       ),
     *      @OA\Response(
     *          response=403,
     *          description="Forbidden",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"26","errors":{"User not found."}},
     *          )
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Entity",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"21","detail":"Validation Failed!","field":{"email":"The email must be a valid email address."}},
     *          )
     *      ),
     * )
     */

    public function forgot(ForgotPasswordRequest $request)
    {
        $data = $this->authService->forgot($request);

        if ($data['status'] != config('staticdata.status_codes.ok')) {
            return $this->formatErrorResponse(
                [$data['message']],
                $data['status'],
                $data['http_code']
            );
        }

        return $this->formatGeneralResponse(
            $data['message'],
            $data['status'],
            $data['http_code']
        );
    }

    /**
     * @OA\Post(
     *      path="api/v1/admin/password/reset",
     *      operationId="resetPasswordAdmin",
     *      tags={"Admin"},
     *      summary="Admin Reset Password",
     *      description="To unlock and retrieve account",
     *      @OA\RequestBody(
     *      required=true,
     *      description="To unlock and retrieve account",
     *      @OA\JsonContent(
     *         required={"email","password","token","password_confirmation"},
     *       @OA\Property(property="email", type="string", format="email", example="user1@mail.com"),
     *       @OA\Property(property="password", type="string", format="password", example="password123"),
     *       @OA\Property(property="token", type="string", format="token", example="token123"),
     *       @OA\Property(property="password_confirmation", type="string", format="password", example="password123"),
     *         ),
     *       ),
     *      @OA\Response(
     *          response=201,
     *          description="Success",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"00","message":"Password reset successful."},
     *          )
     *       ),
     *      @OA\Response(
     *          response=400,
     *          description="Bad Request",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"23","errors":{"Invalid reset token."}},
     *          )
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Entity",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"21","detail":"Validation Failed!","field":{"password":"The password field is required.","email":"The email field is required.","token":"The token field is required."}},
     *          )
     *      ),
     * )
     */

    public function reset(SetPasswordRequest $request)
    {
        $data = $this->authService->reset($request->all());

        if ($data['status'] != config('staticdata.status_codes.ok')) {
            return $this->formatErrorResponse(
                [$data['message']],
                $data['status'],
                $data['http_code']
            );
        }

        return $this->formatGeneralResponse(
            $data['message'],
            $data['status'],
            $data['http_code']
        );
    }


    /**
     * @OA\Post(
     *      path="api/v1/admin/password/validate-reset-token",
     *      operationId="validateResetTokenAdmin",
     *      tags={"Admin"},
     *      summary="Admin Validate Reset Token",
     *      description="To validate reset password token",
     *      @OA\RequestBody(
     *      required=true,
     *      description="To validate reset password token",
     *      @OA\JsonContent(
     *         required={"email","token"},
     *       @OA\Property(property="email", type="string", format="email", example="user1@mail.com"),
     *       @OA\Property(property="token", type="string", format="token", example="token123"),
     *         ),
     *       ),
     *      @OA\Response(
     *          response=201,
     *          description="Success",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"00","message":"Valid reset token."},
     *          )
     *       ),
     *      @OA\Response(
     *          response=400,
     *          description="Bad Request",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"23","errors":{"Invalid reset token."}},
     *          )
     *      ),
     *      @OA\Response(
     *          response=422,
     *          description="Unprocessable Entity",
     *          @OA\JsonContent(
     *              type="string",
     *              example={"status_code":"21","detail":"Validation Failed!","field":{"email":"The email field is required.","token":"The token field is required."}},
     *          )
     *      ),
     * )
     */

    public function validateResetPasswordToken(ValidateResetTokenRequest $request)
    {
        $data = $this->authService->validateResetPasswordToken($request);

        if ($data['status'] != config('staticdata.status_codes.ok')) {
            return $this->formatErrorResponse(
                [$data['message']],
                $data['status'],
                $data['http_code']
            );
        }

        return $this->formatGeneralResponse(
            $data['message'],
            $data['status'],
            $data['http_code']
        );
    }



    public function authCheck()
    {
        $user = auth()->user();
        $data = $this->authService->authCheck($user);

        if ($data == config('messages.authentication.user_location_disabled')) {
            return $this->formatErrorResponse(
                [config('messages.authentication.user_location_disabled')],
                config('staticdata.status_codes.authentication_error'),
                config('staticdata.http_codes.unauthorized')
            );
        }

        //middleware should already performed necessary check
        return $this->formatDataResponse(
            ['user' => $data],
            config('staticdata.status_codes.ok'),
            config('staticdata.http_codes.success')
        );
    }


    public function logout()
    {
        if (auth()->check()) {
            auth()->user()->token()->revoke();
            return $this->formatGeneralResponse(
                config('messages.authentication.authentication_logout_success'),
                config('staticdata.status_codes.ok'),
                config('staticdata.http_codes.success')
            );
        }

        return $this->formatErrorResponse(
            [config('messages.authentication.authentication_error')],
            config('staticdata.status_codes.authentication_error'),
            config('staticdata.http_codes.unauthorized')
        );
    }
}
