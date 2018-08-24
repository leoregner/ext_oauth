<?php

/** @return either an object with the data or throws an exception */
function authenticateToGetData($oauth_uri, $scope)
{
	error_reporting(0);
	session_start();
	$client_id = 1;
	
	$getData = function($oauth_uri, $bearerToken)
	{
		$opts = array('http' => array('method' => 'GET', 'header' => 'Authorization: Bearer ' . $bearerToken));
		$context = stream_context_create($opts);
		$data = file_get_contents("$oauth_uri/api", false, $context);
		if($data === false) throw new \Exception('could not access API');
		$data = json_decode($data, true);
		if($data === null) throw new \Exception('received data is not in JSON format');
		return $data;
	};
	
	if(!isset($_GET['oauth']) || $_GET['oauth'] != 'callback') // start authentication procedure
	{
		if(isset($_SESSION['oauth_bearer'])) // already logged in
			try { return $getData($oauth_uri, $_SESSION['oauth_bearer']); }
			catch(\Exception $x) { /* invalid token, proceed normally */ };
		
		$redirect_uri = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
		$redirect_uri .= (strpos($redirect_uri, '?') !== false ? '&' : '?') . 'oauth=callback';
		$encoded_redirect_uri = urlencode($redirect_uri);
		$state = $_SESSION['oauth_state'] = rand(1, 100000000);
		$encoded_scope = urlencode($scope);
		
		header('HTTP/1.1 302 Found');
		header("Location: $oauth_uri/auth?response_type=code&client_id=$client_id&redirect_uri=$encoded_redirect_uri&scope=$scope&state=$state");
		exit;
	}
	
	else // process callback
	{
		if(isset($_GET['error']))
			throw new \Exception($_GET['error']);
		
		if(!isset($_GET['code']) || !($_GET['state']) || $_GET['state'] != $_SESSION['oauth_state'])
			throw new \Exception('invalid response received');
		
		$req = array('grant_type' => 'authorization_code', 'client_id' => $client_id, 'code' => $_GET['code']);
		$opts = array('http' => array('method' => 'POST', 'header' => 'Content-type: application/x-www-form-urlencoded', 'content' => http_build_query($req)));
		$context = stream_context_create($opts);
		$data = file_get_contents("$oauth_uri/token", false, $context);
		if($data === false) throw new \Exception('could not get access token');
		$data = json_decode($data, true);
		if($data === null) throw new \Exception('received data is not in JSON format');
		
		if(!isset($data['access_token']) || !isset($data['token_type']) || $data['token_type'] != 'bearer')
			throw new \Exception('token of unknown type received');
		
		$bearerToken = $_SESSION['oauth_bearer'] = $data['access_token'];
		return $getData($oauth_uri, $bearerToken);
	}
}

?>