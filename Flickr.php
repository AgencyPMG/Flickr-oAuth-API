<?PHP
/*
Created by Chris Alvares from PMG (Performance Media Group)
@email: chris.alvares@pmg.co
@website: pmg.co
MIT License
*/

class Flickr
{
	
	public $config;
	
	
	public function __construct()
	{
		@session_start();
		$this->config = array(
			/*You can get a consumer key here: http://www.flickr.com/services/api/ */
			'consumer_key' => 'YOUR CONSUMER KEY HERE',
			'consumer_secret' => 'YOUR CONSUMER SECRET HERE',
			'apiversion' => '1.0',
			'flickr_APIURL' => 'http://www.flickr.com/services/oauth',
			'debug' => true
		);
		
	}
	
	
	public function isLoggedIn()
	{
	
		//you can implement this method yourself if you want to store into the database
		$loginInfo = $this->getLoginInformation();
		
		if(isset($loginInfo['flickr_perm_token']) && isset($loginInfo['flickr_perm_secret']))
		{
			return true;
		}
	
		return false;
	}
	
	public function saveLoginInformation($oauth_token, $oauth_token_secret, $user_nsid)
	{
		//you can implement this method yourself if you want to store into the database
		$_SESSION['flickr_perm_token'] = $oauth_token;
		$_SESSION['flickr_perm_secret'] = $oauth_token_secret;
		$_SESSION['flickr_current_userid'] = $user_nsid;
	}
	
	
	/*
	 $info['flickr_perm_token']
	 $info['flickr_perm_secret']
	 $info['flickr_current_userid']
	*/
	
	public function getLoginInformation()
	{
		//you can implement this method yourself if you want to store into the database
		$info = array();
		if(isset($_SESSION['flickr_perm_token'])) $info['flickr_perm_token'] = $_SESSION['flickr_perm_token'];
		if(isset($_SESSION['flickr_perm_secret'])) $info['flickr_perm_secret'] = $_SESSION['flickr_perm_secret'];	
		if(isset($_SESSION['flickr_current_userid'])) $info['flickr_current_userid'] = $_SESSION['flickr_current_userid'];	

		return $info;
	}
	
	
	public function signIntoFlickr()
	{
		if($this->isLoggedIn()) return true;

		if(isset($_GET["oauth_token"]) && isset($_GET["oauth_verifier"]))
		{
			
			$accessURL = $this->getAccessURL($_GET['oauth_token'],$_GET['oauth_verifier']);
			$params = $this->cURL($accessURL);
			
			unset($_SESSION['flickr_temp_token']);
			unset($_SESSION['flickr_temp_token_secret']);
			
			parse_str($params);
			
			if(isset($oauth_token) && isset($oauth_token_secret) && isset($user_nsid))
			{
				$this->saveLoginInformation($oauth_token, $oauth_token_secret, $user_nsid);
			}
			return true;
		}
		
		
		
		$authURL = $this->getAuthURL();
		$params = $this->cURL($authURL);
		
		parse_str($params);
		
		if(!isset($oauth_callback_confirmed) || !isset($oauth_token))
		{
			$this->debug('Can not connect to flickr, try again later');
			$this->debug($params);
			return;
		}
		
		@session_start();
		$_SESSION['flickr_temp_token'] = $oauth_token;
		$_SESSION['flickr_temp_token_secret'] = $oauth_token_secret;
		
		$url = $this->config['flickr_APIURL'] . '/authorize?oauth_token=' . $oauth_token;
		header("location: $url");
		exit();
		
		return false;
	}
	
	
	public function getAccessURL($oauth_token, $oauth_verifier)
	{
	
		@session_start();
		$params = array(
			'oauth_consumer_key' => $this->config['consumer_key'],
			'oauth_nonce'=> md5(microtime() . mt_rand()),
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' =>time(),
			'oauth_token' => $oauth_token,
			'oauth_verifier' => $oauth_verifier,
			'oauth_version' => $this->config['apiversion']
		);
			
			
		$baseURL = $this->config['flickr_APIURL'] . '/access_token';
		
		return $this->getSignedURL($baseURL, $params, $_SESSION['flickr_temp_token_secret']);
	
	}
	
	
	public function getAuthURL($callback=null)
	{
		if($callback == null) 
			$callback = (!empty($_SERVER['HTTPS'])) ? "https://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'] : "http://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
		
		$baseURL = $this->config['flickr_APIURL'] . '/request_token';
		
		$params = array(
			'oauth_callback'=> urlencode($callback),
			'oauth_consumer_key'=> $this->config['consumer_key'],
			'oauth_nonce' => md5(microtime() . mt_rand()),
			'oauth_signature_method' => 'HMAC-SHA1',
			'oauth_timestamp' => time(),
			'oauth_version' => $this->config['apiversion']
		);
		
		return $this->getSignedURL($baseURL, $params);
	}
	
	
	public function getSignedURL($baseURL, $params=null, $request_serect="", $method='GET')
	{
		if($params == null) $params = array();
		//first sort the URL by lexicon order
		$paramskeys = array_keys($params);
		asort($paramskeys);
		
		$purl = "";
		
		for($i=0;$i<sizeof($paramskeys);$i++)
		{
			if($i!=0)$purl .= '&';
			$purl .= $paramskeys[$i] . '=' . $params[$paramskeys[$i]];
		}
		
		
		$text = 'GET&' . urlencode($baseURL) . '&' . urlencode($purl);
		$key = $this->config['consumer_secret'] . '&' . $request_serect;
		
		$sig = base64_encode(hash_hmac('sha1', $text, $key, true));
		
		return $baseURL . '?' . $purl . '&oauth_signature=' . urlencode($sig);
		
		
	}	
	
	protected function debug($info)
	{
		if($this->config["debug"])
			echo $info . "<BR /><BR />";
	}
	
	protected function cURL($url)
	{
		$ch  = curl_init($url);
		curl_setopt($ch,CURLOPT_USERAGENT,'FLICKR PHP API');
		curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($ch,CURLOPT_CONNECTTIMEOUT,5);
		curl_setopt($ch,CURLOPT_FOLLOWLOCATION,1);
		if(strtolower(parse_url($url, PHP_URL_SCHEME)) == 'https')
		{
			curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,FALSE);
			curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,FALSE);
		}
		$str = curl_exec($ch);

		curl_close($ch);

		return $str;   

	}

}









?>