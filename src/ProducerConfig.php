<?php
declare(strict_types=1);

namespace Kafka;

use Kafka\Protocol\Produce;
use function in_array;

/**
 * @method int getRequestTimeout()
 * @method int getProduceInterval()
 * @method int getTimeout()
 * @method int getRequiredAck()
 * @method bool getIsAsyn()
 * @method int getCompression()
 */
class ProducerConfig extends Config
{
    use SingletonTrait;

    private const COMPRESSION_OPTIONS = [
        Produce::COMPRESSION_NONE,
        Produce::COMPRESSION_GZIP,
        Produce::COMPRESSION_SNAPPY,
    ];

    /**
     * @var mixed[]
     */
    protected $extDefaults = [
        'requiredAck'     => 1,
        'timeout'         => 5000,
        'isAsyn'          => false,
        'requestTimeout'  => 6000,
        'produceInterval' => 100,
        'compression'     => Protocol\Protocol::COMPRESSION_NONE,
    ];

    public function __construct()
    {
        parent::__construct();
    }

    /**
     * @param int $requestTimeout
     * @throws \Kafka\Exception\Config
     */
    public function setRequestTimeout(int $requestTimeout): void
    {
        if ($requestTimeout < 1 || $requestTimeout > 900000) {
            throw new Exception\Config('Set request timeout value is invalid, must set it 1 .. 900000');
        }

        $this->options['requestTimeout'] = $requestTimeout;
    }

    /**
     * @param int $produceInterval
     * @throws \Kafka\Exception\Config
     */
    public function setProduceInterval(int $produceInterval): void
    {
        if ($produceInterval < 1 || $produceInterval > 900000) {
            throw new Exception\Config('Set produce interval timeout value is invalid, must set it 1 .. 900000');
        }

        $this->options['produceInterval'] = $produceInterval;
    }

    /**
     * @param int $timeout
     * @throws \Kafka\Exception\Config
     */
    public function setTimeout(int $timeout): void
    {
        if ($timeout < 1 || $timeout > 900000) {
            throw new Exception\Config('Set timeout value is invalid, must set it 1 .. 900000');
        }

        $this->options['timeout'] = $timeout;
    }

    /**
     * @param int $requiredAck
     * @throws \Kafka\Exception\Config
     */
    public function setRequiredAck(int $requiredAck): void
    {
        if ($requiredAck < -1 || $requiredAck > 1000) {
            throw new Exception\Config('Set required ack value is invalid, must set it -1 .. 1000');
        }

        $this->options['requiredAck'] = $requiredAck;
    }

    /**
     * @param bool $asyn
     */
    public function setIsAsyn(bool $asyn): void
    {
        $this->options['isAsyn'] = $asyn;
    }

    /**
     * @param int $compression
     */
    public function setCompression(int $compression): void
    {
        if (! in_array($compression, self::COMPRESSION_OPTIONS, true)) {
            throw new Exception\Config('Compression must be one the Kafka\Protocol\Produce::COMPRESSION_* constants');
        }

        $this->options['compression'] = $compression;
    }
}
