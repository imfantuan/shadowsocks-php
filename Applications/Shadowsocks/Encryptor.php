<?php
/**
 * This file is part of workerman.
 *
 * Licensed under The MIT License
 * For full copyright and license information, please see the MIT-LICENSE.txt
 * Redistributions of files must retain the above copyright notice.
 *
 * @author walkor<walkor@workerman.net>
 * @copyright walkor<walkor@workerman.net>
 * @link http://www.workerman.net/
 * @license http://www.opensource.org/licenses/mit-license.php MIT License
 */

/**
 * 加密解密类
 * @author walkor<walkor@workerman.net>
 */
class Encryptor
{
    protected $_password;
    protected $_key;
    protected $_method;
    protected $_cipher;
    protected $_decipher;
    protected $_bytesToKeyResults = array();
    protected $_send_iv;
    protected $_recv_iv;
    protected $_ivSent;
    protected $_onceMode;
    protected static $_methodSupported = array(
        'none'=> array(16, 0),
        'aes-128-cfb'=> array(16, 16),
        'aes-192-cfb'=> array(24, 16),
        'aes-256-cfb'=> array(32, 16),
        'bf-cfb'=> array(16, 8),
        'camellia-128-cfb'=> array(16, 16),
        'camellia-192-cfb'=> array(24, 16),
        'camellia-256-cfb'=> array(32, 16),
        'cast5-cfb'=> array(16, 8),
        'des-cfb'=> array(8, 8),
        'idea-cfb'=>array(16, 8),
        'rc2-cfb'=> array(16, 8),
        'seed-cfb'=> array(16, 16),
        'rc4'=> array(16, 0),
        'rc4-md5'=> array(16, 16),
        'rc4-md5-6'=> array(16, 6),
        'aes-128-ctr'=> array(16, 16), //gmp, OpenSSL
        'aes-192-ctr'=> array(24, 16), //gmp, OpenSSL
        'aes-256-ctr'=> array(32, 16), //gmp, OpenSSL
        'chacha20'=> array(32, 8),  //OpenSSL
        'chacha20-ietf'=> array(32, 12),  //OpenSSL
        'aes-128-gcm'=> array(16, 16),  //(PHP >= 7.1.0) OpenSSL 对于AEAD，第二个参数是salt长度
        'aes-192-gcm'=> array(24, 24),  //(PHP >= 7.1.0) OpenSSL
        'aes-256-gcm'=> array(32, 32),  //(PHP >= 7.1.0) OpenSSL or Sodium
        'chacha20-poly1305'=> array(32, 32),  //(PHP >= 7.2.0) Sodium
        'chacha20-ietf-poly1305'=> array(32, 32),  //(PHP >= 7.2.0) Sodium
        'xchacha20-ietf-poly1305'=> array(32, 32),  //(PHP >= 7.2.0) Sodium
    );

    public function __construct($key, $method, $onceMode = false)
    {
        $this->_password = $key;
        $this->_method = strtolower($method);
        $this->_ivSent = false;
        $this->_onceMode = $onceMode;
        $iv_len = $this->getCipherLen($this->_method);
        $iv_len = $iv_len[1];
        $iv = $iv_len ? openssl_random_pseudo_bytes($iv_len) : null;
        $this->_cipher = $this->getCipher($this->_password, $this->_method, 1, $iv);
    }

    protected function getCipher($password, $method, $op, $iv)
    {
        $m = $this->getCipherLen($method);
        if($m) {
            $ref = $this->EVPBytesToKey($password, $m[0], $m[1]);
            $this->_key = $key = $ref[0];
            $iv_ = $ref[1];
            if ($iv == null) {
                $iv = $iv_;
            }
            $iv = substr($iv, 0, $m[1]);
            if ($op === 1) {
                $this->_send_iv = $iv;
            } else {
                $this->_recv_iv = $iv;
            }
            switch($method) {
                case 'none':
                    return new NoneEncipher();
                case 'rc4':
                    return new RC4Encipher($key);
                case 'rc4-md5':
                case 'rc4-md5-6':
                    $rc4_key = md5($key.$iv, true);
                    return new RC4Encipher($rc4_key);
                case 'aes-128-gcm':
                case 'aes-192-gcm':
                case 'aes-256-gcm':
                case 'chacha20-poly1305':
                case 'chacha20-ietf-poly1305':
                case 'xchacha20-ietf-poly1305':
                    $salt = $iv;
                    if($op === 1) {
                        return new AEADEncipher($method, $key, $salt, $this->_onceMode);
                    } else {
                        return new AEADDecipher($method, $key, $salt, $this->_onceMode);
                    }
                case 'aes-128-ctr':
                case 'aes-192-ctr':
                case 'aes-256-ctr':
                case 'chacha20':
                case 'chacha20-ietf':
                    return new CtrEncipher($method, $key, $iv);
                default:
                    if($op === 1) {
                        return new CfbEncipher($method, $key, $iv);
                    } else {
                        return new CfbDecipher($method, $key, $iv);
                    }
            }
        }
    }

    public function getKey()
    {
        return $this->_key;
    }

    public function getIV($send = false)
    {
        if($send)
            return $this->_send_iv;
        else
            return $this->_recv_iv;
    }

    public function encrypt($buffer)
    {
        if($this->_method) {
            $result = $this->_cipher->update($buffer);
            if ($this->_ivSent) {
                return $result;
            } else {
              $this->_ivSent = true;
              return $this->_send_iv . $result;
            }
        }
    }

    public function decrypt($buffer)
    {
        if($this->_method) {
            if(!$this->_decipher) {
                $decipher_iv_len = $this->getCipherLen($this->_method);
                $decipher_iv_len = $decipher_iv_len[1];
                $decipher_iv = substr($buffer, 0, $decipher_iv_len);
                $this->_decipher = $this->getCipher($this->_password, $this->_method, 0, $decipher_iv);
                $result = $this->_decipher->update(substr($buffer, $decipher_iv_len));
                return $result;
            } else {
                $result = $this->_decipher->update($buffer);
                return $result;
            }
        }
    }

    protected function EVPBytesToKey($password, $key_len, $iv_len)
    {
        $cache_key = "$password:$key_len:$iv_len";
        if(isset($this->_bytesToKeyResults[$cache_key])) {
            return $this->_bytesToKeyResults[$cache_key];
        }
        $m = array();
        $i = 0;
        $count = 0;
        while ($count < $key_len + $iv_len) {
            $data = $password;
            if ($i > 0) {
                $data = $m[$i-1] . $password;
            }
            $d = md5($data, true);
            $m[] = $d;
            $count += strlen($d);
            $i += 1;
        }
        $ms = '';
        foreach($m as $buf) {
           $ms .= $buf;
        }
        $key = substr($ms, 0, $key_len);
        $iv =  substr($ms, $key_len, $key_len + $iv_len);
        $this->bytesToKeyResults[$password] = array($key, $iv);
        return array($key, $iv);
    }
    
    protected function getCipherLen($method)
    {
        return isset(self::$_methodSupported[$method]) ? self::$_methodSupported[$method] : null;
    }
}

class NoneEncipher
{
    public function update($data)
    {
        return $data;
    }
}

class RC4Encipher
{
    protected $s;
    protected $_i;
    protected $_j;

    public function __construct($key)
    {
        $this->s = array();
        for ($i=0; $i<256; $i++) {
            $this->s[$i] = $i;
        }

        $j = 0;
        $key_len = strlen($key);
        for ($i=0; $i<256; $i++) {
            $j = ($j + $this->s[$i] + ord($key[$i % $key_len])) % 256;
            //swap
            $x = $this->s[$i];
            $this->s[$i] = $this->s[$j];
            $this->s[$j] = $x;
        }
        $this->_i = 0;
        $this->_j = 0;
    }

    public function update($data)
    {
        $i = $this->_i;
        $j = $this->_j;
        $out_buf = '';
        $data_len = strlen($data);
        for ($y=0; $y< $data_len; $y++) {
            $i = ($i + 1) % 256;
            $j = ($j + $this->s[$i]) % 256;
            //swap
            $x = $this->s[$i];
            $this->s[$i] = $this->s[$j];
            $this->s[$j] = $x;
            $out_buf .= $data[$y] ^ chr($this->s[($this->s[$i] + $this->s[$j]) % 256]);
        }
        $this->_i = $i;
        $this->_j = $j;
        return $out_buf;
    }
}

class CtrEncipher
{
    const BLOCK_SIZE = 64;
    protected $_algorithm;
    protected $_algorithm_openssl;
    protected $_key;
    protected $_tail;
    protected $_block_size;

    public function __construct($algorithm, $key, $iv)
    {
        $this->_algorithm = $algorithm;
        $this->_key = $key;
        $this->_nonce = $iv;
        if(function_exists('gmp_init')) {
            $this->_counter = gmp_init('0');
            $this->_gmp_support = true;
        } else {
            $this->_counter = 0;
            $this->_gmp_support = false;
        }
        if(strpos($algorithm, "chacha20") !== false) {
            $this->_block_size = static::BLOCK_SIZE;
            $this->_algorithm_openssl = 'chacha20';
        } else {
            $this->_block_size = openssl_cipher_iv_length($this->_algorithm);
            $this->_algorithm_openssl = $this->_algorithm;
        }
    }

    public function update($data)
    {
        if (strlen($data) == 0)
            return '';
        if($this->_gmp_support) {
            $iv = $this->counter_mode_gen_iv_by_gmp();
            $this->_counter =  gmp_add($this->_counter, strval(strlen($data)) );
        } else {
            $iv = $this->counter_mode_gen_iv();
            $this->_counter += strlen($data);
        }

        $tl = strlen($this->_tail);
        if ($tl)
            $data = $this->_tail . $data;
        $b = openssl_encrypt($data, $this->_algorithm_openssl, $this->_key, OPENSSL_RAW_DATA, $iv);
        $result = substr($b, $tl);
        $dataLength = strlen($data);
        $mod = $dataLength % $this->_block_size;
        $this->_tail = $mod!=0 ? substr($data, -$mod):'';
        return $result;
    }

    protected function counter_mode_gen_iv_by_gmp()
    {
        $counter = gmp_div_q($this->_counter, strval($this->_block_size));
        switch($this->_algorithm) {
            case 'chacha20-ietf':
                //more: https://libsodium.gitbook.io/doc/advanced/stream_ciphers/chacha20
                /* The IETF variant increases the nonce size to 96 bits,
                 * but reduces the counter size down to 32 bits, allowing 
                 * only up to 256 GB of data to be safely encrypted with a 
                 * given (key, nonce) pair.
                 */
                $counter_pack = gmp_export($counter, 4, GMP_LSW_FIRST);
                $counter_pack = str_pad($counter_pack, 4, "\0", STR_PAD_LEFT);
                return $counter_pack . $this->_nonce;
            case 'chacha20':
                /* The original ChaCha20 cipher with a 64-bit nonce and a 64-bit counter,
                 * allowing a practically unlimited amount of data to be encrypted with the same
                 * (key, nonce) pair 
                 */
                $counter_pack = gmp_export($counter, 8, GMP_LSW_FIRST);
                $counter_pack = str_pad($counter_pack, 8, "\0", STR_PAD_LEFT);
                return $counter_pack . $this->_nonce;
            case 'aes-128-ctr':
            case 'aes-192-ctr':
            case 'aes-256-ctr':
                $nonce = gmp_import($this->_nonce, 1, GMP_MSW_FIRST);
                $counter_pack = gmp_export(gmp_add($nonce, $counter), 1, GMP_MSW_FIRST);
                $counter_pack = str_pad($counter_pack, 16, "\0", STR_PAD_LEFT);
                return $counter_pack;
            default:
                return $this->_iv;
        }
    }

    protected function counter_mode_gen_iv()
    {
        $counter = intval($this->_counter / $this->_block_size);
        switch($this->_algorithm) {
            case 'chacha20-ietf':
                $counter_pack = pack("V", $counter);
                return $counter_pack . $this->_nonce;
            case 'chacha20':
                /* 此处为了兼容32位系统，使用32位counter */
                $counter_pack = pack("V2", $counter, 0);
                return $counter_pack . $this->_nonce;
            case 'aes-128-ctr':
            case 'aes-192-ctr':
            case 'aes-256-ctr':
                $counter_pack = pack("N", $counter);
                return $this->msb_number_add($this->_nonce, $counter_pack);
            default:
                return  $this->_iv;
        }
    }

    protected function msb_number_add($a, $b)
    {
        $la = strlen($a);
        $lb = strlen($b);
        if($la > $lb) {
            $base = strrev($a);
            $add = strrev($b);
            $base_len = $la;
            $add_len = $lb;
        } else {
            $base = strrev($b);
            $add = strrev($a);
            $base_len = $lb;
            $add_len = $la;
        }
        $c = 0;
        for($i=0; $i<$base_len; $i++) {
            if($i < $add_len)
                $c += ord($add[$i]);
            $sum = $c + ord($base[$i]);
            $base[$i] = chr($sum % 256);
            $c = intval($sum / 256);
        }
        return strrev($base);
    }
}

class CfbEncipher
{
    protected $_algorithm;
    protected $_algorithm_openssl;
    protected $_key;
    protected $_iv;
    protected $_tail;
    protected $_block_size;

    public function __construct($algorithm, $key, $iv)
    {
        $this->_algorithm = $algorithm;
        $this->_key = $key;
        $this->_iv = $iv;
        $this->_block_size = openssl_cipher_iv_length($this->_algorithm);
    }

    public function update($data)
    {
        if (strlen($data) == 0)
            return '';
        $tl = strlen($this->_tail);
        if ($tl)
            $data = $this->_tail . $data;
        $b = openssl_encrypt($data, $this->_algorithm, $this->_key, OPENSSL_RAW_DATA, $this->_iv);
        $result = substr($b, $tl);
        $dataLength = strlen($data);
        $mod = $dataLength % $this->_block_size;
        if ($dataLength >= $this->_block_size) {
            $iPos = -($mod + $this->_block_size);
            $this->_iv = substr($b, $iPos, $this->_block_size);
        }
        $this->_tail = $mod!=0 ? substr($data, -$mod):'';
        return $result;
    }
}

class CfbDecipher extends CfbEncipher
{
    public function update($data)
    {
        if (strlen($data) == 0)
            return '';
        $tl = strlen($this->_tail);
        if ($tl)
            $data = $this->_tail . $data;
        $b = openssl_decrypt($data, $this->_algorithm, $this->_key, OPENSSL_RAW_DATA, $this->_iv);
        $result = substr($b, $tl);
        $dataLength = strlen($data);
        $mod = $dataLength % $this->_block_size;
        if ($dataLength >= $this->_block_size) {
            $iPos = -($mod + $this->_block_size);
            $this->_iv = substr($data, $iPos, $this->_block_size);
        }
        $this->_tail = $mod!=0 ? substr($data, -$mod):'';
        return $result;
    }
}

class AEADEncipher
{
    const CHUNK_SIZE_LEN    = 2;
    const AEAD_TAG_LEN      = 16;

    const CRYPTO_ERROR      = -1;
    const CRYPTO_NEED_MORE  = 0;
    const CRYPTO_OK         = 1;

    const CHUNK_SIZE_MASK   = 0x3FFF;
    protected $_algorithm;
    protected $_aead_tail;
    protected $_aead_subkey;
    protected $_aead_iv;
    protected $_aead_chunk_id;
    protected $_aead_encipher_all;
    protected $_sodium_support;

    protected static $_methodSupported = array(
        'aes-128-gcm'=> array(16, 12),
        'aes-192-gcm'=> array(24, 12),
        'aes-256-gcm'=> array(32, 12),
        'chacha20-poly1305'=> array(32, 8),
        'chacha20-ietf-poly1305'=> array(32, 12),
        'xchacha20-ietf-poly1305'=> array(32, 24),
    );

    public function __construct($algorithm, $key, $salt, $all = false)
    {
        $this->_algorithm = $algorithm;
        $this->_aead_tail = '';
        $iv_len = self::$_methodSupported[$algorithm][1];
        $this->_aead_iv = str_repeat("\x00", $iv_len);
        /* subkey生成 */
        $this->_aead_subkey = hash_hkdf("sha1", $key, strlen($key), "ss-subkey", $salt);
        $this->_aead_chunk_id = 0;
        $this->_aead_encipher_all = $all;
        if(function_exists('sodium_increment')) {
            $this->_sodium_support = true;
        } else {
            $this->_sodium_support = false;
        }
    }

    public function update($data)
    {
        //UDP
        if($this->_aead_encipher_all) {
            $err = $this->aead_encrypt_all($this->_aead_iv, $this->_aead_subkey, $data);
            if($err == static::CRYPTO_ERROR) {
                echo "[" .__FILE__ . " " . __LINE__ . "]" . "AEAD encrypt error\n";
                return '';
            }
            return $data;
        }
        //TCP
        $result = '';
        while(strlen($data) > 0) {
            $temp = '';
            $err = $this->aead_chunk_encrypt($this->_aead_iv, $this->_aead_subkey, $data, $temp);
            if($err == static::CRYPTO_ERROR) {
                echo "[" .__FILE__ . " " . __LINE__ . "]" . "AEAD encrypt error\n";
                return '';
            }
            $result .= $temp;
        }
        
        return $result;
    }

    protected function aead_encrypt_all(&$iv, $subkey, &$buffer)
    {
        /*
         * Shadowsocks AEAD chunk:
         *
         *  +-------------------+-------------+
         *  | encrypted payload | payload tag |
         *  +-------------------+-------------+
         *  |        n          |     16      |
         *  +-------------------+-------------+
         *
         */
        $buffer = $this->aead_encrypt($buffer, '', $iv, $subkey);
        return static::CRYPTO_OK;
    }

    protected function aead_chunk_encrypt(&$iv, $subkey, &$buffer, &$result)
    {
        /*
         * Shadowsocks AEAD chunk:
         *
         *  +--------------------------+------------+-------------------+-------------+
         *  | encrypted payload length | length tag | encrypted payload | payload tag |
         *  +--------------------------+------------+-------------------+-------------+
         *  |             2            |     16     |        n          |     16      |
         *  +--------------------------+------------+-------------------+-------------+
         *
         */
        $plen = strlen($buffer);
        if($plen > static::CHUNK_SIZE_MASK) {
            $plen = static::CHUNK_SIZE_MASK;
        }
        $data = substr($buffer, 0, $plen);
        $plen_bin = pack('n', $plen);
        $result .= $this->aead_encrypt($plen_bin, '', $iv, $subkey);
        if(strlen($result) !=  static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN) {
            return static::CRYPTO_ERROR;
        }
        if($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $result .= $this->aead_encrypt($data, '', $iv, $subkey);
        if(strlen($result) !=  2*static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN + $plen) {
            return static::CRYPTO_ERROR;
        }
        if($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $this->_aead_chunk_id++;
        $buffer = substr($buffer, $plen);
        return static::CRYPTO_OK;
    }

    protected function aead_encrypt($msg, $ad, $nonce, $key)
    {
        if($this->_sodium_support) {
            switch($this->_algorithm) {
            case 'aes-256-gcm':
                return sodium_crypto_aead_aes256gcm_encrypt($msg, $ad, $nonce, $key);
            case 'chacha20-poly1305':
                return sodium_crypto_aead_chacha20poly1305_encrypt($msg, $ad, $nonce, $key);
            case 'chacha20-ietf-poly1305':
                return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($msg, $ad, $nonce, $key);
            case 'xchacha20-ietf-poly1305':
                return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($msg, $ad, $nonce, $key);
            default:
                ;
            }
        }
        switch($this->_algorithm) {
            case 'aes-128-gcm':
            case 'aes-192-gcm':
            case 'aes-256-gcm':
                $tag = '';
                $data = openssl_encrypt($msg, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
                return $data . $tag;
            default:
                echo "unsupported encryption algorithm, please enable sodium expansion\n";
                return '';
        }
    }

    protected function nonce_increment(&$nonce)
    {
        $c = 1;
        $len = strlen($nonce);
        for($i=0; $i<$len; $i++) {
            $c += ord($nonce[$i]);
            $nonce[$i] = chr($c & 0xff);
            $c >>= 8;
        }
    }
}

class AEADDecipher extends AEADEncipher
{
    public function update($data)
    {
        //UDP
        if($this->_aead_encipher_all) {
            $err = $this->aead_decrypt_all($this->_aead_iv, $this->_aead_subkey, $data);
            if($err == static::CRYPTO_ERROR) {
                echo "[" .__FILE__ . " " . __LINE__ . "]" . "AEAD decrypt error\n";
                return '';
            }
            return $data;
        }
        //TCP
        $tl = strlen($this->_aead_tail);
        if($tl) {
            $data = $this->_aead_tail . $data;
            $this->_aead_tail = '';
        }

        $result = '';
        while(strlen($data) > 0) {
            $err = $this->aead_chunk_decrypt($this->_aead_iv, $this->_aead_subkey, $data, $result);
            if($err == static::CRYPTO_ERROR) {
                echo "[ " . __LINE__ . "]" . "AEAD decrypt error\n";
                return '';
            } else if($err == static::CRYPTO_NEED_MORE) {
                if( strlen($data) == 0 ) {
                    echo "[ " . __LINE__ . "]" . "AEAD decrypt error\n";
                    return '';
                } else {
                    $this->_aead_tail .= $data;
                    //echo "[ " . __LINE__ . "]" . "AEAD decrypt tail\n";
                    break;
                }
            }
        }
        
        return $result;
    }

    public function aead_decrypt_all(&$iv, $subkey, &$buffer)
    {
        /*
         * Shadowsocks AEAD chunk:
         *
         *  +-------------------+-------------+
         *  | encrypted payload | payload tag |
         *  +-------------------+-------------+
         *  |        n          |     16      |
         *  +-------------------+-------------+
         *
         */
        //验证chunk长度
        if(strlen($buffer) <= static::AEAD_TAG_LEN) {
            return static::CRYPTO_ERROR;
        }

        $buffer = $this->aead_decrypt($buffer, '', $iv, $subkey);
        return static::CRYPTO_OK;
    }

    protected function aead_chunk_decrypt(&$iv, $subkey, &$buffer, &$result)
    {
        /*
         * Shadowsocks AEAD chunk:
         *
         *  +--------------------------+------------+-------------------+-------------+
         *  | encrypted payload length | length tag | encrypted payload | payload tag |
         *  +--------------------------+------------+-------------------+-------------+
         *  |             2            |     16     |        n          |     16      |
         *  +--------------------------+------------+-------------------+-------------+
         *
         */
        //验证chunk长度
        if(strlen($buffer) <= 2 * static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN) {
            return static::CRYPTO_NEED_MORE;
        }

        $payload_length_enc_length = static::AEAD_TAG_LEN + static::CHUNK_SIZE_LEN;
        $payload_length_enc = substr($buffer, 0, $payload_length_enc_length);

        $mlen = $this->aead_decrypt($payload_length_enc, '', $iv, $subkey);
        if(strlen($mlen) != static::CHUNK_SIZE_LEN) {
            echo "[ " . __LINE__ . "]" . "mlen error! id: " . $this->_aead_chunk_id . "\n";
            return static::CRYPTO_ERROR;
        }
        $payload_length = unpack('n', $mlen);
        $payload_length = intval($payload_length[1]) & static::CHUNK_SIZE_MASK;
        $payload_enc_length = $payload_length + static::AEAD_TAG_LEN;
        //验证payload长度
        if(strlen($buffer) - $payload_length_enc_length < $payload_enc_length) {
            return static::CRYPTO_NEED_MORE;
        }
        $buffer = substr($buffer, $payload_length_enc_length);
        $payload_enc = substr($buffer, 0, $payload_enc_length);
        $buffer = substr($buffer, $payload_enc_length);
        if($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $result .= $this->aead_decrypt($payload_enc, '', $iv, $subkey);
        if($this->_sodium_support)
            sodium_increment($iv);
        else
            $this->nonce_increment($iv);
        $this->_aead_chunk_id++;
        return static::CRYPTO_OK;
    }

    protected function aead_decrypt($msg, $ad, $nonce, $key)
    {
        if($this->_sodium_support) {
            switch($this->_algorithm) {
            case 'aes-256-gcm':
                return sodium_crypto_aead_aes256gcm_decrypt($msg, $ad, $nonce, $key);
            case 'chacha20-poly1305':
                return sodium_crypto_aead_chacha20poly1305_decrypt($msg, $ad, $nonce, $key);
            case 'chacha20-ietf-poly1305':
                return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($msg, $ad, $nonce, $key);
            case 'xchacha20-ietf-poly1305':
                return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($msg, $ad, $nonce, $key);
            default:
                ;
            }
        }
        switch($this->_algorithm) {
            case 'aes-128-gcm':
            case 'aes-192-gcm':
            case 'aes-256-gcm':
                $data_len = strlen($msg) - static::AEAD_TAG_LEN;
                $data = substr($msg, 0, $data_len);
                $tag = substr($msg, $data_len);
                return openssl_decrypt($data, $this->_algorithm, $key, OPENSSL_RAW_DATA, $nonce, $tag, $ad);
            default:
                echo "unsupported encryption algorithm, please enable sodium expansion\n";
                return '';
        }
    }
}
