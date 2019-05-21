<?php
/**
 * This file is a part of "furqansiddiqui/ecdsa-php" package.
 * https://github.com/furqansiddiqui/ecdsa-php
 *
 * Copyright (c) 2019 Furqan A. Siddiqui <hello@furqansiddiqui.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code or visit following link:
 * https://github.com/furqansiddiqui/ecdsa-php/blob/master/LICENSE
 */

declare(strict_types=1);

namespace FurqanSiddiqui\ECDSA\OpenSSL;

use FurqanSiddiqui\DataTypes\Base64;
use FurqanSiddiqui\DataTypes\Binary;
use FurqanSiddiqui\DataTypes\Buffer\AbstractStringType;

/**
 * Class PEM_Certificate
 * @package FurqanSiddiqui\ECDSA\OpenSSL
 */
class PEM_Certificate extends AbstractStringType
{
    /**
     * PEM_Certificate constructor.
     * @param string|null $pem
     * @param bool $validate
     */
    public function __construct(?string $pem = null, bool $validate = true)
    {
        if ($validate) {
            if (!preg_match('/^[-]{5}[\w\s]+[-]{5}\n[a-z0-9\+\/\=\n]+[-]{5}[\w\s]+[-]{5}[\n]?$/i', $pem)) {
                throw new \InvalidArgumentException('Invalid PEM certificate');
            }
        }

        parent::__construct($pem);
    }

    /**
     * @return string
     */
    public function __toString(): string
    {
        return $this->data;
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
        $split = preg_split('/[-]{5}[\w\s]+[-]{5}/i', $this->data);
        $body = implode("", explode($eol, trim($split[1])));
        return new Base64($body);
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
        $pem .= chunk_split($data->get()->base64(), 64, $eol);
        $pem .= sprintf("-----END %s-----", $type) . $eol;

        return (new self($pem, false))->readOnly(true);
    }
}