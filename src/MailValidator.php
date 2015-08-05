<?php

namespace Goodmain\MailValidator;

/**
 * Validate Email Addresses Via SMTP
 */
class MailValidator
{

    /**
     * PHP Socket resource to remote MTA
     * @var resource $sock
     */
    private $socket;

    /**
     * List of domains to validate users on
     * @var array
     */
     private $domains;

    /**
     * SMTP Port
     * @var int
     */
    private $port = 25;

    /**
     * Maximum Connection Time to wait for connection establishment per MTA
     * @var int
     */
    private $maxConnectionTime = 30;

    /**
     * Maximum time to read from socket before giving up
     * @var int
     */
    private $maxReadTime = 5;

    /**
     * Username of sender
     */
    private $fromUser = 'user';

    /**
     * Host Name of sender
     */
    private $fromDomain = 'localhost';

    /**
     * Servers to use when make DNS query for MX entries
     * @var array $servers
     */
    private $servers = [
        '192.168.0.1'
    ];

    private $debug = false;

    /**
     * @param string|bool $sender - Email of validator
     */
    public function __construct($sender = false)
    {
        if ($sender) {
            $this->setSenderEmail($sender);
        }
    }

    /**
     * Set the Emails to validate
     * @param array|string $emails
     */
    public function setEmails($emails)
    {
        $this->domains = [];

        foreach ((array)$emails as $email) {
            $parts = explode('@', $email);
            if (count($parts) == 2) {
                if (!isset($this->domains[$parts[1]])) {
                    $this->domains[$parts[1]] = [];
                }
                $this->domains[$parts[1]][] = $parts[0];
            }
        }
    }

    /**
     * Set Email of validator
     * @param string $sender
     */
    public function setSenderEmail($sender)
    {
        $parts = explode('@', $sender);

        if (count($parts) == 2) {
            $this->fromUser = $parts[0];
            $this->fromDomain = $parts[1];
        }
    }

    /**
     * @param int $port
     */
    public function setPort($port)
    {
        $this->port = $port;
    }

    /**
     * @param int $maxConnectionTime
     */
    public function setMaxConnectionTime($maxConnectionTime)
    {
        $this->maxConnectionTime = $maxConnectionTime;
    }

    /**
     * @param int $maxReadTime
     */
    public function setMaxReadTime($maxReadTime)
    {
        $this->maxReadTime = $maxReadTime;
    }

    /**
     * Set servers for name resolving
     * @param array $servers
     */
    public function setServers($servers)
    {
        $this->servers = $servers;
    }

    /**
     * Validate Email Addresses
     * @param array|bool $emails - List of Emails to Validate
     * @return array - Associative List of Emails and their validation results
     */
    public function validate($emails = false)
    {
        $results = [];

        if ($emails) {
            $this->setEmails($emails);
        }

        // query the MTAs on each Domain
        foreach ($this->domains as $domain => $users) {

            $mxs = [];

            // retrieve SMTP Server via MX query on domain
            list($hosts, $mxWeights) = $this->queryMX($domain);

            // retrieve MX priorities
            for ($n = 0; $n < count($hosts); $n++) {
                $mxs[$hosts[$n]] = $mxWeights[$n];
            }
            asort($mxs);

            // last fallback is the original domain
            $mxs[$domain] = 0;

            $this->debug(print_r($mxs, 1));

            $timeout = $this->maxConnectionTime;

            // try each host
            while (list($host) = each($mxs)) {
                // connect to SMTP server
                $this->debug("try $host:$this->port\n");
                if ($this->socket = @fsockopen($host, $this->port, $errno, $errstr, (float)$timeout)) {
                    stream_set_timeout($this->socket, $this->maxReadTime);
                    break;
                }
            }

            // did we get a TCP socket
            if ($this->socket) {
                $reply = fread($this->socket, 2082);
                $this->debug("<<<\n$reply");

                preg_match('/^([0-9]{3}) /ims', $reply, $matches);
                $code = isset($matches[1]) ? $matches[1] : '';

                if ($code != '220') {
                    // MTA gave an error...
                    foreach ($users as $user) {
                        $results[$user . '@' . $domain] = $reply;
                    }
                    continue;
                }

                // say helo
                $this->send("HELO " . $this->fromDomain);
                // tell of sender
                $this->send("MAIL FROM: <" . $this->fromUser . '@' . $this->fromDomain . ">");

                // ask for each recipient on this domain
                foreach ($users as $user) {

                    // ask of recipient
                    $reply = $this->send("RCPT TO: <" . $user . '@' . $domain . ">");

                    // get code and msg from response
                    preg_match('/^([0-9]{3}) /ims', $reply, $matches);
                    $code = isset($matches[1]) ? $matches[1] : '';

                    if ($code == '250') {
                        // you received 250 so the email address was accepted
                        $results[$user . '@' . $domain] = true;
                    } elseif ($code == '451' || $code == '452') {
                        // you received 451 so the email address was greylisted
                        // (or some temporary error occurred on the MTA) - so assume is ok
                        $results[$user . '@' . $domain] = true;
                    } else {
                        $results[$user . '@' . $domain] = $reply;
                    }
                }

                // reset before quit
                $this->send("RSET");

                // quit
                $this->send("quit");
                // close socket
                fclose($this->socket);
            } else {
                foreach ($users as $user) {
                    $results[$user . '@' . $domain] = 'Connection time out';
                }
            }
        }

        return $results;
    }


    private function send($msg)
    {
        fwrite($this->socket, $msg . "\r\n");

        $reply = fread($this->socket, 2082);

        $this->debug(">>>\n$msg\n");
        $this->debug("<<<\n$reply");

        return $reply;
    }

    /**
     * Query DNS server for MX entries
     * @param string $domain
     * @return array
     */
    private function queryMX($domain)
    {
        $hosts = [];
        $mxWeights = [];
        if (function_exists('getmxrr')) {
            getmxrr($domain, $hosts, $mxWeights);
        } else {
            // windows, we need Net_DNS
            require_once 'Net/DNS.php';

            $resolver = new Net_DNS_Resolver();
            $resolver->debug = $this->debug;
            // servers to query
            $resolver->nameservers = $this->servers;
            $resp = $resolver->query($domain, 'MX');
            if ($resp) {
                foreach ($resp->answer as $answer) {
                    $hosts[] = $answer->exchange;
                    $mxWeights[] = $answer->preference;
                }
            }

        }
        return [$hosts, $mxWeights];
    }

    private function debug($str)
    {
        if ($this->debug) {
            echo '<pre>' . htmlentities($str) . '</pre>';
        }
    }
}