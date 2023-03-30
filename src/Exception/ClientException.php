<?php

declare(strict_types=1);

/*
 * This file is part of Ymir PHP SDK.
 *
 * (c) Carl Alexander <support@ymirapp.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Ymir\Sdk\Exception;

use GuzzleHttp\Exception\ClientException as GuzzleClientException;
use Illuminate\Support\Collection;
use Psr\Http\Message\ResponseInterface;

/**
 * Exception thrown when the HTTP client encounters an error.
 */
class ClientException extends \RuntimeException
{
    /**
     * The Guzzle response.
     *
     * @var ResponseInterface
     */
    private $response;

    /**
     * Constructor.
     */
    public function __construct(GuzzleClientException $exception)
    {
        $this->response = $exception->getResponse();

        $message = $this->getApiErrorMessage();

        if (empty($message)) {
            $message = $this->getDefaultMessage($exception->getCode());
        } elseif (in_array($exception->getCode(), [400, 422])) {
            $message = $this->getValidationErrorMessage();
        }

        parent::__construct($message, $exception->getCode());
    }

    /**
     * Get the validation errors that the API sent back.
     */
    public function getValidationErrors(): Collection
    {
        $body = collect(json_decode((string) $this->response->getBody(), true));
        $errors = $body->only(['errors'])->collapse();

        if ($errors->isEmpty() && $body->has('message')) {
            $errors->add($body->get('message'));
        }

        return $errors;
    }

    /**
     * Get the Ymir API error message.
     */
    private function getApiErrorMessage(): string
    {
        $body = (string) $this->response->getBody();
        $decodedBody = json_decode($body, true);

        return JSON_ERROR_NONE === json_last_error() && !empty($decodedBody['message']) ? $decodedBody['message'] : str_replace('"', '', $body);
    }

    /**
     * Get the default exception message based on the exception code.
     */
    private function getDefaultMessage(int $code): string
    {
        $message = '';

        if (401 === $code) {
            $message = 'Authentication is required to perform this action';
        } elseif (402 === $code) {
            $message = 'An active subscription is required to perform this action';
        } elseif (403 === $code) {
            $message = 'You are not authorized to perform this action';
        } elseif (404 === $code) {
            $message = 'The requested resource does not exist';
        } elseif (409 === $code) {
            $message = 'This operation is already in progress';
        } elseif (410 === $code) {
            $message = 'The requested resource is being deleted';
        } elseif (429 === $code) {
            $message = 'You are attempting this action too often';
        }

        return $message;
    }

    /**
     * Get the validation error messages from the ClientException.
     */
    private function getValidationErrorMessage(): string
    {
        $errors = $this->getValidationErrors()->flatten();
        $message = 'The Ymir API responded with validation errors';

        if ($errors->isEmpty()) {
            return $message;
        }

        $message .= ":\n";

        foreach ($errors as $error) {
            $message .= "\n    * {$error}";
        }

        return $message;
    }
}
