<?php
class XUpload {
    // private class members
    private $url              = '';
    private $path             = '';
    private $workers          = 1;
    private $progress         = null;
    private $size             = 0;
    private $csize            = 0;
    private $clients          = [];
    private $scheduler        = [];
    private $proxySocket      = null;
    private $proxyCredentials = null;

    // public interface
    public function __construct($url, $path, $workers = 1, $progress = null, $proxy = []) {
        if (!preg_match('@^https?://@', $url) || ($info = @stat($path)) === false || $info['size'] <= 0) {
            return;
        }
        $this->url      = $url;
        $this->path     = $path;
        $this->size     = $info['size'];
        $this->workers  = intval(max(1, min($workers, $this->size / (4<<20))));
        $this->progress = $progress;
        if (count($proxy) === 2) {
            $this->proxySocket      = $proxy[array_key_first($proxy)];
            $this->proxyCredentials = $proxy[array_key_last($proxy)];
        }
        $this->csize    = $this->size / $this->workers;
        if (($value = intval($this->size / $this->workers / (4<<20))) > 0) {
            $this->csize /= $value;
        }
        $this->csize     = intval($this->csize);
        $this->scheduler = curl_multi_init();
        $chunks          = intval(round($this->size / $this->csize / $this->workers));
        for ($index = 0; $index < $this->workers; $index++) {
            $request = curl_init();
            curl_setopt_array($request, [
                CURLOPT_PRIVATE        => $index,
                CURLOPT_URL            => $this->url,
                CURLOPT_PROXY          => $this->proxySocket,
                CURLOPT_PROXYUSERPWD   => $this->proxyCredentials,
                CURLOPT_UPLOAD         => true,
                CURLOPT_HEADER         => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CUSTOMREQUEST  => 'POST',
                CURLOPT_READFUNCTION   => function($request, $unused, $size) {
                    $client = $this->clients[$index = curl_getinfo($request, CURLINFO_PRIVATE)];
                    $size   = min($size, $client['size'] - $client['sent']);
                    $this->clients[$index]['sent'] += $size;
                    return substr($client['data'], $client['sent'], $size);
                },
            ]);
            $this->clients[] = [
                'request' => $request,
                'start'   => $index * $this->csize * $chunks,
                'offset'  => $index * $this->csize * $chunks,
                'end'     => $index == $this->workers - 1 ? $this->size - 1 : (($index + 1) * $this->csize * $chunks) - 1,
                'size'    => 0,
                'sent'    => 0,
            ];
            curl_multi_add_handle($this->scheduler, $request);
        }
    }
    public function start()
    {
        if ($this->url == '' || $this->path == '' || $this->size == 0 ) {
            return [
                'error' => [
                    'code'    => 400,
                    'message' => 'invalid parameters'
                ]
            ];
        }
        for ($index = 0; $index < $this->workers; $index++) {
            $this->run($index);
        }
        $response = [];
        $last     = microtime(true);
        if ($this->progress !== null) {
            call_user_func($this->progress, 0, $this->size);
        }
        do {
            while (($status = curl_multi_exec($this->scheduler, $active)) == CURLM_CALL_MULTI_PERFORM);
            if ($this->progress !== null && (($now = microtime(true)) - $last) > 0.3) {
                $last = $now;
                $sent = 0;
                for ($index = 0; $index < $this->workers; $index ++) {
                    $client = $this->clients[$index];
                    $sent += $client['offset'] - $client['start'] + 1 + $client['sent'];
                }
                if (call_user_func($this->progress, min($sent, $this->size), $this->size) !== true) {
                    $response = [
                        'error' => [
                            'code'    => 400,
                            'message' => 'upload cancelled'
                        ]
                    ];
                    break;
                }
            }
            if ($active) {
                curl_multi_select($this->scheduler);
            }
            while (($request = curl_multi_info_read($this->scheduler)) !== false) {
                $info     = curl_getinfo($request['handle']);
                $response = curl_multi_getcontent($request['handle']);
                $ranges   = [];
                if (preg_match(sprintf('@Range: ((?:\d+-\d+,?)+)/%d@s', $this->size), substr($response, 0, @$info['header_size']), $matches)) {
                    foreach (explode(',', $matches[1]) as $range) {
                        list($low, $high) = explode('-', $range, 2);
                        $ranges[] = [ intval($low), intval($high) ];
                    }
                }
                $response = @json_decode(substr($response, @$info['header_size']), true);
                switch ($info['http_code'])
                {
                    case 200:
                        if ($this->progress !== null) {
                            call_user_func($this->progress, $this->size, $this->size);
                        }
                        break;
                    case 202:
                    case 416:
                        $client = $this->clients[$index = curl_getinfo($request['handle'], CURLINFO_PRIVATE)];
                        foreach ($ranges as $range) {
                            if ($client['start'] >= $range[0] && $client['start'] < $range[1]) {
                                if ($client['end'] <= $range[1]) {
                                    $response = [];
                                    break;
                                }
                                if (($range[1] - $client['start'] + 1) % $this->csize == 0) {
                                    $this->clients[$index]['offset'] = $range[1] + 1;
                                    $this->run($index);
                                    $response = [];
                                    break;
                                }
                            }
                        }
                        break;

                    default:
                        if (@$response['error'] == '') {
                            $response = [
                                'error' => [
                                    'code'    => 503,
                                    'message' => 'server unavailable'
                                ]
                            ];
                        }
                        break;
                }
            }
        } while ($status == CURLM_OK && count($response) == 0);
        for ($index = 0; $index < $this->workers; $index++) {
            curl_multi_remove_handle($this->scheduler, $this->clients[$index]['request']);
            curl_close($this->clients[$index]['request']);
        }
        curl_multi_close($this->scheduler);
        return $response;
    }

    // internal functions
    private function run($index) {
        $client = $this->clients[$index];
        $size   = min($this->csize,  $client['end'] - $client['offset'] + 1);
        $this->clients[$index]['data'] = file_get_contents($this->path, false, null,  $client['offset'], $size);
        $this->clients[$index]['size'] = $size;
        $this->clients[$index]['sent'] = 0;
        curl_multi_remove_handle($this->scheduler, $client['request']);
        curl_setopt_array($client['request'], [
            CURLOPT_INFILESIZE => $size,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/octet-stream',
                "Content-Disposition: attachment; filename*=UTF-8''" . rawurlencode(basename($this->path)),
                sprintf('Content-Range: bytes %d-%d/%d', $client['offset'], $client['offset'] + $size - 1, $this->size),
            ],
        ]);
        curl_multi_add_handle($this->scheduler, $client['request']);
    }
}
