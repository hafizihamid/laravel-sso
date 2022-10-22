<?php

namespace App\Http\Controllers\Api;

use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;

class ApiController extends BaseController
{
    use AuthorizesRequests;
    use DispatchesJobs;

    protected $statusCode;
    protected $httpCode;

    public function __construct()
    {
        $this->statusCode = config('staticdata.status_codes');
        $this->httpCode = config('staticdata.http_codes');
    }

    public function formatPaginatedDataResponse($message, $statusCode, $httpCode)
    {
        $response = [
            'status_code' => $statusCode,
        ];
        $response = array_merge($response, $message->toArray());

        return response()->json($response, $httpCode);
    }

    public function formatDataResponse($message, $statusCode, $httpCode)
    {
        $response = [
            'status_code' => $statusCode,
            'data' => $message
        ];

        return response()->json($response, $httpCode);
    }

    public function formatGeneralResponse($message, $statusCode, $httpCode)
    {
        $response = [
            'status_code' => $statusCode,
            'message' => $message
        ];

        return response()->json($response, $httpCode);
    }

    public function formatErrorResponse($data, $statusCode = null, $http_response = null)
    {
        $statusCode = $statusCode ?? config('staticdata.status_codes.error');
        $http_response = $http_response ?? config('staticdata.http_codes.internal_server_error');

        $message = [
            'status_code' => $statusCode,
            'errors' => $data,
        ];

        return response()->json($message, $http_response);
    }

    public function formatResourceResponse($data, $user_id = null, $http_response = null, $message = null)
    {
        $statusCode = $statusCode ?? config('staticdata.status_codes.ok');
        $http_response = $http_response ?? config('staticdata.http_codes.success');

        $response = [
            'status_code' => $statusCode,
            'data' => $data
        ];

        if ($message) {
            $response['message'] = $message;
        }

        if ($user_id) {
            $response['user_id'] = $user_id;
        }

        return response()->json($response, $http_response);
    }

    public function formatValidationResponse($data, $statusCode = null, $http_response = null)
    {
        $statusCode = $statusCode ?? config('staticdata.status_codes.validation_failed');
        $http_response = $http_response ?? config('staticdata.http_codes.unprocessable_entity');

        $message = [
            'status_code' => $statusCode,
            'detail' => config('messages.general.validation_failed'),
            'field' => $data
        ];

        return response()->json($message, $http_response);
    }
}
