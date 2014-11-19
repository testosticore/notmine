<?php
/*
Plugin Name: yourls-phishtank
Plugin URI: http://pof.eslack.org/
Description: Prevent shortening malware URLs using phishtank API
Version: 0.1
Author: Pau Oliva Fora
Author URI: http://pof.eslack.org/
*/

yourls_add_filter( 'pre_add_new_link', 'pof_pre_new_link' );
function pof_pre_new_link($args) {

        // if you have an application key, enter it here, otherwise your requests will be rate limited by phishtank
        $KEY="";

        $API="http://checkurl.phishtank.com/checkurl/";
        $url=urlencode($args[0]);

        $ch = curl_init();
        curl_setopt ($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt ($ch, CURLOPT_POST, TRUE);
        curl_setopt ($ch, CURLOPT_USERAGENT, "x90");
        curl_setopt ($ch, CURLOPT_POSTFIELDS, "format=xml&app_key=$KEY&url=$url");
        curl_setopt ($ch, CURLOPT_URL, "$API");
        $result = curl_exec($ch);
        curl_close($ch);

        if (preg_match("/phish_detail_page/",$result)) {
                yourls_die( 'The requested URL cannot be shortened.', 'Forbidden', 403 );
                die();
        }
}