<?php

/**
 * Validate Email Addresses Via SMTP
 */
class MailValidator
{

    /**
     * PHP Socket resource to remote MTA
     * @var resource $sock
     */
    var $sock;

    /**
     * Current User being validated
     */
    var $user;

    /**
     * List of domains to validate users on
     * @var array
     */
    var $domains;

    /**
     * SMTP Port
     * @var int
     */
    var $port = 25;

    /**
     * Maximum Connection Time to wait for connection establishment per MTA
     * @var int
     */
    var $maxConnectionTime = 30;

    /**
     * Maximum time to read from socket before giving up
     * @var int
     */
    var $maxReadTime = 5;

    /**
     * username of sender
     */
    var $fromUser = 'user';

    /**
     * Host Name of sender
     */
    var $fromDomain = 'localhost';

    /**
     * Nameservers to use when make DNS query for MX entries
     * @var array $nameservers
     */
    var $nameservers = [
        '192.168.0.1'
    ];

    var $debug = false;

    /**
     * Initializes the Class
     * @param array|bool $emails - List of Emails to Validate
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
     * @param array $emails - List of Emails
     */
    public function setEmails($emails)
    {
        foreach ($emails as $email) {
            list($user, $domain) = $this->parseEmail($email);
            if (!isset($this->domains[$domain])) {
                $this->domains[$domain] = [];
            }
            $this->domains[$domain][] = $user;
        }
    }

    /**
     * Set the Email of the sender/validator
     * @param string $email
     */
    public function setSenderEmail($email)
    {
        $parts = $this->parseEmail($email);
        $this->from_user = $parts[0];
        $this->from_domain = $parts[1];
    }

    /**
     * Validate Email Addresses
     * @param array|bool $emails - List of Emails to Validate
     * @param string|bool $sender - Email of validator
     * @return array Associative List of Emails and their validation results
     */
    function validate($emails = false, $sender = false)
    {
        $results = [];

        if ($emails) {
            $this->setEmails($emails);
        }
        if ($sender) {
            $this->setSenderEmail($sender);
        }

        // query the MTAs on each Domain
        foreach ($this->domains as $domain => $users) {

            $mxs = [];

            // current domain being queried
            $this->domain = $domain;

            // retrieve SMTP Server via MX query on domain
            list($hosts, $mxweights) = $this->queryMX($domain);

            // retrieve MX priorities
            for ($n = 0; $n < count($hosts); $n++) {
                $mxs[$hosts[$n]] = $mxweights[$n];
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
                if ($this->sock = fsockopen($host, $this->port, $errno, $errstr, (float)$timeout)) {
                    stream_set_timeout($this->sock, $this->maxReadTime);
                    break;
                }
            }

            // did we get a TCP socket
            if ($this->sock) {
                $reply = fread($this->sock, 2082);
                $this->debug("<<<\n$reply");

                preg_match('/^([0-9]{3}) /ims', $reply, $matches);
                $code = isset($matches[1]) ? $matches[1] : '';

                if ($code != '220') {
                    // MTA gave an error...
                    foreach ($users as $user) {
                        $results[$user . '@' . $domain] = false;
                    }
                    continue;
                }

                // say helo
                $this->send("HELO " . $this->fromDomain);
                // tell of sender
                $this->send("MAIL FROM: <" . $this->fromUser . '@' . $this->fromDomain . ">");

                // ask for each recepient on this domain
                foreach ($users as $user) {

                    // ask of recepient
                    $reply = $this->send("RCPT TO: <" . $user . '@' . $domain . ">");

                    // get code and msg from response
                    preg_match('/^([0-9]{3}) /ims', $reply, $matches);
                    $code = isset($matches[1]) ? $matches[1] : '';

                    if ($code == '250') {
                        // you received 250 so the email address was accepted
                        $results[$user . '@' . $domain] = true;
                    } elseif ($code == '451' || $code == '452') {
                        // you received 451 so the email address was greylisted (or some temporary error occured on the MTA) - so assume is ok
                        $results[$user . '@' . $domain] = true;
                    } else {
                        $results[$user . '@' . $domain] = false;
                    }

                }

                // reset before quit
                $this->send("RSET");

                // quit
                $this->send("quit");
                // close socket
                fclose($this->sock);

            }
        }
        return $results;
    }


    function send($msg)
    {
        fwrite($this->sock, $msg . "\r\n");

        $reply = fread($this->sock, 2082);

        $this->debug(">>>\n$msg\n");
        $this->debug("<<<\n$reply");

        return $reply;
    }

    /**
     * Query DNS server for MX entries
     * @return
     */
    function queryMX($domain)
    {
        $hosts = [];
        $mxweights = [];
        if (function_exists('getmxrr')) {
            getmxrr($domain, $hosts, $mxweights);
        } else {
            // windows, we need Net_DNS
            require_once 'Net/DNS.php';

            $resolver = new Net_DNS_Resolver();
            $resolver->debug = $this->debug;
            // nameservers to query
            $resolver->nameservers = $this->nameservers;
            $resp = $resolver->query($domain, 'MX');
            if ($resp) {
                foreach ($resp->answer as $answer) {
                    $hosts[] = $answer->exchange;
                    $mxweights[] = $answer->preference;
                }
            }

        }
        return [$hosts, $mxweights];
    }

    /**
     * Simple function to replicate PHP 5 behaviour. http://php.net/microtime
     */
    function microtime_float()
    {
        list($usec, $sec) = explode(" ", microtime());
        return ((float)$usec + (float)$sec);
    }

    function debug($str)
    {
        if ($this->debug) {
            echo '<pre>' . htmlentities($str) . '</pre>';
        }
    }
//---------------------------
    private function parseEmail($email)
    {
        $parts = explode('@', $email);
        $domain = array_pop($parts);
        $user = implode('@', $parts);
        return [$user, $domain];
    }
}