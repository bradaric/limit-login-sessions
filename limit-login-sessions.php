<?php
/*
Plugin Name: Limit Login Sessions
Version: 1.0.0
Author: Sisir Kanti Adhikari
Author URI: https://sisir.me/
Description: Limits users login sessions.
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Limit Login Sessions is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
any later version.
 
Limit Login Sessions is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License (http://www.gnu.org/licenses/gpl-2.0.html)
 for more details.

*/

add_filter('authenticate', 'lls_authenticate', 1000, 2);

function lls_authenticate($user, $username){

    // 1. Get all active session for this user
    if(!username_exists($username) || !$user = get_user_by('login', $username))
        return null; // will trigger WP default no username/password matched error

    // setup vars
    $max_sessions = 5;
    $max_oldest_allowed_session_hours = 4;
    $error_code = 'max_session_reached';
    $error_message = "Maximum $max_sessions login sessions are allowed. Please contact site administrator.";

    $manager = WP_Session_Tokens::get_instance( $user->ID );
    $sessions =  $manager->get_all();

    // 2. Count all active session
    $session_count = count($sessions);

    // 3. Return okay if active session less then $max_sessions
    if($session_count < $max_sessions)
        return $user;

    $oldest_activity_session = lls_get_oldest_activity_session($sessions);

    // 4. If active sessions is equal to 5 then check if a session has no activity last 4 hours
    // 5. if oldest session have activity return error
    if(
        ( $session_count >= $max_sessions && !$oldest_activity_session ) // if no oldest is found do not allow
        || ( $session_count >= $max_sessions && $oldest_activity_session['last_activity'] + $max_oldest_allowed_session_hours * HOUR_IN_SECONDS > time())
    ){
        return new WP_Error($error_code, $error_message);
    }

    // 5. Oldest activity session doesn't have activity is given recent hours
    // destroy oldest active session and authenticate the user

    $verifier = lls_get_verifier_by_session($oldest_activity_session, $user->ID);

    lls_destroy_session($verifier, $user->ID);

    return $user;

}

function lls_destroy_session($verifier, $user_id){

    $sessions = get_user_meta( $user_id, 'session_tokens', true );

    if(!isset($sessions[$verifier]))
        return true;

    unset($sessions[$verifier]);

    if(!empty($sessions)){
        update_user_meta( $user_id, 'session_tokens', $sessions );
        return true;
    }

    delete_user_meta( $user_id, 'session_tokens');
    return true;

}

function lls_get_verifier_by_session($session, $user_id = null){

    if(!$user_id)
        $user_id = get_current_user_id();

    $session_string = implode(',', $session);
    $sessions = get_user_meta( $user_id, 'session_tokens', true );

    if(empty($sessions))
        return false;

    foreach($sessions as $verifier => $sess){
        $sess_string = implode(',', $sess);

        if($session_string == $sess_string)
            return $verifier;

    }

    return false;
}


function lls_get_oldest_activity_session($sessions){
    $sess = false;

    foreach($sessions as $session){

        if(!isset($session['last_activity']))
            continue;

        if(!$sess){
            $sess = $session;
            continue;
        }

        if($sess['last_activity'] > $session['last_activity'])
            $sess = $session;

    }

    return $sess;
}

// add a new key to session token array

add_filter('attach_session_information', 'lls_attach_session_information');

function lls_attach_session_information($session){
    $session['last_activity'] = time();
    return $session;
}

add_action('template_redirect', 'lls_update_session_last_activity');

function lls_update_session_last_activity(){

    if(!is_user_logged_in())
        return;

    // get the login cookie from browser
    $logged_in_cookie = $_COOKIE[LOGGED_IN_COOKIE];

    // check for valid auth cookie
    if( !$cookie_element = wp_parse_auth_cookie($logged_in_cookie) )
        return;

    // get the current session
    $manager = WP_Session_Tokens::get_instance( get_current_user_id() );

    $current_session = $manager->get($cookie_element['token']);

    if(
        $current_session['expiration'] <= time() // only update if session is not expired
        || ( $current_session['last_activity'] + 5 * MINUTE_IN_SECONDS ) > time() // only update in every 5 min to reduce db load
    ){
        return;
    }

    $current_session['last_activity'] = time();
    $manager->update($cookie_element['token'], $current_session);

}

