<?php
/*
Plugin Name: yourls-virustotal
Plugin URI: http://x90.es/
Description: Prevent malware URLs using virustotal urlscan API
Version: 0.1
Author: pof
Author URI: http://pof.eslack.org/
*/

if( !defined( 'YOURLS_ABSPATH' ) ) die(); // No direct call

// On creation, check if this is malware
yourls_add_filter( 'pre_add_new_link', 'pof_pre_new_link' );
function pof_pre_new_link($args) {

        // virustotal api key, enter it here. 
        $KEY="";

        $API="https://www.virustotal.com/api/get_url_report.json";
        $url=urlencode($args[0]);

        $ch = curl_init();
        curl_setopt ($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt ($ch, CURLOPT_POST, TRUE);
        curl_setopt ($ch, CURLOPT_USERAGENT, "x90");
        curl_setopt ($ch, CURLOPT_POSTFIELDS, "scan=1&key=$KEY&resource=$url");
        curl_setopt ($ch, CURLOPT_URL, "$API");
        $result = curl_exec($ch);
        curl_close($ch);

        if (preg_match("/Malware site/",$result) || preg_match("/Phishing site/",$result) ) {
                echo "The requested URL cannot be shortened.";
                die();
        }
}


// On redirection, check if this is malware
yourls_add_action( 'pre_redirect', 'pof_malware_check' );
function pof_malware_check( $args ) {

        // virustotal api key, enter it here. 
        $KEY="";

        $API="https://www.virustotal.com/api/get_url_report.json";
        $url=$args[0];

        $ch = curl_init();
        curl_setopt ($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt ($ch, CURLOPT_POST, TRUE);
        curl_setopt ($ch, CURLOPT_USERAGENT, "x90");
        curl_setopt ($ch, CURLOPT_POSTFIELDS, "scan=0&key=$KEY&resource=$url");
        curl_setopt ($ch, CURLOPT_URL, "$API");
        $result = curl_exec($ch);
        curl_close($ch);

        if (preg_match("/Malware site/",$result) || preg_match("/Phishing site/",$result) ) {

                // Draw the warning page itself.
                yourls_html_head();
echo <<<PAGE
        <h2>WARNING: Possible malware / phishing / scam URL</h2>
        <p>You were being redirected to <strong>$url</strong> which has been detected as posibly malicious by <a href="http://www.virustotal.com/about.html">VirusTotal</a>.</p>
        <p><strong>This site might be harmful to your computer</strong>. <a href="$url">Click here</a> to access this site at your own risk.</p>
</div>
</body>
</html>
PAGE;
                die();
        } else {
                return;
        }
}
?>