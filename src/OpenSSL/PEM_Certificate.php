<?php
/*
 * This file is a part of "furqansiddiqui/ecdsa-php" package.
 * https://github.com/furqansiddiqui/ecdsa-php
 *
 * Copyright (c) Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/ecdsa-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\ECDSA\OpenSSL;

use Comely\DataTypes\Buffer\AbstractBuffer;
use Comely\DataTypes\Buffer\Base64;
use Comely\DataTypes\Buffer\Binary;

/**
 * Class PEM_Certificate
 * @package FurqanSiddiqui\ECDSA\OpenSSL
 */
class PEM_Certificate extends AbstractBuffer
{
    /**
     * @param string|null $data
     * @return string
     */
    public function validatedDataTypeValue(?string $data): string
    {
        if (!is_string($data) || !preg_match('/^[-]{5}[\w\s]+[-]{5}\n[a-z0-9+\/=\n]+[-]{5}[\w\s]+[-]{5}[\n]?$/i', $data)) {
            throw new \InvalidArgumentException('Invalid PEM certificate');
        }

        return $data;
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->value();
    }

    /**
     * @param string $eol
     * @return Binary
     */
    public function toDER(string $eol = "\n"): Binary
    {
        return $this->der($eol);
    }

    /**
     * @param string $eol
     * @return Binary
     */
    public function der(string $eol = "\n"): Binary
    {
        $split = preg_split('/[-]{5}[\w\s]+[-]{5}/i', $this->value());
        $body = implode("", explode($eol, trim($split[1])));
        return (new Base64($body))->binary();
    }

    /**
     * @param Binary $data
     * @param string $type
     * @param string $eol
     * @return PEM_Certificate
     */
    public static function fromDER(Binary $data, string $type = "PRIVATE KEY", string $eol = "\n"): self
    {
        $type = strtoupper($type);
        $pem = sprintf("-----BEGIN %s-----", $type) . $eol;
        $pem .= chunk_split($data->base64()->encoded(), 64, $eol);
        $pem .= sprintf("-----END %s-----", $type) . $eol;

        return (new self($pem))->readOnly(true);
    }
}
