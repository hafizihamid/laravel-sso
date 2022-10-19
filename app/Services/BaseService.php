<?php

namespace App\Services;

class BaseService
{
    public function formatGeneralResponse($message, $status, $http_code)
    {
        $response = [
            'status' => $status,
            'http_code' => $http_code,
            'message' => $message
        ];

        return $response;
    }
}
