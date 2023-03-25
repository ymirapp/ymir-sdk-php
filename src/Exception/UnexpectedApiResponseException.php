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

/**
 * Exception thrown when the API fails to return an expected response.
 */
class UnexpectedApiResponseException extends \RuntimeException
{
}
