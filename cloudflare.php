<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
/**
 * Cloudflare Client API Interface Library
 *
 * @author		Dustin Blake (Circuitbomb)
 * @copyright	Copyright (c) 2012, Dustin Blake (http://circuitbomb.com)
 * @license		WTFPL found at http://sam.zoy.org/wtfpl/COPYING
 * @link		https://github.com/circuitbomb/Cloudflare-for-CodeIgniter
 *
 * Does not yet implement: 
 *	-A NAME record updating
 *	-DNS record deletion
 *	-New DNS Record creation
 *	
 */
 
/**
 * Cloudflare
 *
 * @package		CodeIgniter
 * @subpackage	Libraries
 * @category	APIs/Cloudflare
 * @author		Dustin Blake (Circuitbomb)
 * @link		https://github.com/circuitbomb/Cloudflare-for-CodeIgniter
 */

class Cloudflare {

	private $api_Url = "https://www.cloudflare.com/api_json.html?";		//Request URL
	private $log_Path = "define-a-path/";								//Path to log requests with trailing slash
	private $token = "your-cloudflare-token";							//Cloudflare API key
	private $email = "your-email-address";								//Associated Email address
	private $default_Zone = "a-default-zone";                           //Default Zone (e.g. example.com)
	
	private $data;
	
	public function __construct()
	{
		$this->data = array('tkn' => $this->token, 'email' => $this->email);
	}
	
	/**
	* Makes POST request via cURL to Cloudflare API writing to file and returning data, Cloudflare ClientAPI is rate limited to 300/hr
	* @access   private
	* @param	array
	* @return	json
	*/
	private function retrieve_Data($array)
	{
		if(array_key_exists('z', $array) && is_null($array['z']))
		{
			$array['z'] = $this->defZone;
		}
		
		$init = curl_init();
		
		$fp = fopen($this->log_Path . "cloudflare_".$array['a']."-".date("Y-m-d").".txt", "a");
		
		curl_setopt($init, CURLOPT_URL, $this->api_Url);
		curl_setopt($init, CURLOPT_FORBID_REUSE, TRUE);
		curl_setopt($init, CURLOPT_SSL_VERIFYPEER, FALSE);
		curl_setopt($init, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($init, CURLOPT_POST, 1);
		curl_setopt($init, CURLOPT_POSTFIELDS, $array);
		
		$exec = curl_exec($init);
		$error = curl_error($init);
		$code = curl_getinfo($init, CURLINFO_HTTP_CODE);
		
		if($code != 200)
		{
			$exec = json_encode(array("error" => $error));
		}
		
		fwrite($fp, $exec);
		curl_close($init);
		fclose($fp);
		
		return $exec;
	}
	
	/**
	* Retrieve the current stats and settings for a particular website. This function can be used to get currently settings of values such as the security level.
	* @access	public
	* @param	integer
	* @param	string or NULL
	* @return	json
	*
	* Accepted time interval values, the latest data is from one day ago
	*	10 = Past 365 days
	*	20 = Past 30 days
	*	30 = Past 7 days
	*	40 = Past day
	*
	* These values are for Pro accounts
	*	100 = 24 hours ago
	*	110 = 12 hours ago
	*	120 = 6 hours ago
	*/
	public function get_Stats($interval = 40, $zone = NULL)
	{
		$this->data['a'] = 'stats';
		$this->data['z'] = $zone;
		$this->data['interval'] = $interval;
			
		return $this->retrieve_Data($this->data);
	}
	
	/**
	* This lists all domains in a CloudFlare account along with other data.
	* @access	public
	* @param
	* @return	json
	*/
	public function get_MultiZone()
	{	
		$this->data['a'] = 'zone_load_multi';
		return $this->retrieve_Data($this->data);
	}
	
	/**
	* Lists all of the DNS records from a particular domain in a CloudFlare account
	* @access	public
	* @param	string or NULL
	* @return	json
	*/
	public function get_DnsRec($zone = NULL)
	{
		$this->data['a'] = 'rec_load_all';
		$this->data['z'] = $zone;

		return $this->retrieve_Data($this->data);
	}
	
	/*
	* Checks for active zones and returns their corresponding zone ids
	* @access	public
	* @param 	string or NULL
	* @return 	json
	*
	* The param string may be a comma separated list of zones
	*/
	public function check_Zone($zone = NULL)
	{
		$this->data['a'] = 'zone_check';
		$this->data['z'] = $zone;
		
		return $this->retrieve_Data($this->data);
	}
	
	/*
	* Returns a list of IP addresses which hit your site classified by type.
	* @access	public
	* @param	integer
	* @param	string
	* @param	bool integer
	* @param	string or NULL
	* @return	json
	*
	* Hours, between 24 to 48 max
	* Class, optional restrictions
	*	n = none
	*	r = regular
	*	s = crawler
	*	t = threat
	*
	* Geo, optional, set to 1 to add longitude and latitude
	*/
	public function get_IpsRecent($hours = 24, $class = "r", $geo = 1, $zone = NULL)
	{
		$data['a'] = 'zone_ips';
		$data['hours'] = $hours;
		$data['z'] = $zone;
		
		if($class == "r" || $class == "s" || $class == "t") 
		{ 
			$data['class'] = $class;
		}
		
		if($geo == 1)
		{
			$data['geo'] = $geo;
		}
		
		return $this->retrieve_Data($this->data);
	
	}
	
	/*
	* Find the current threat score for a given IP. Note that scores are on a logarithmic scale, where a higher score indicates a higher threat.
	* @access	public
	* @param	string
	* @return	json
	*/
	public function get_IpsScore($ip_address = NULL)
	{
		$this->data['a'] = 'ip_lkup';
		$this->data['ip'] = $ip_address;

		return $this->retrieve_Data($this->data);
	}
	
	/*
	* Sets the Basic Security Level to I'M UNDER ATTACK! / HIGH / MEDIUM / LOW / ESSENTIALLY OFF.
	* @access	public
	* @param	string
	* @param	string or NULL
	* @return	json
	*
	* Security Levels
	*	help - I'm under attack
	*	high - High
	*	med  - Medium
	*	low  - Low
	*	eoff - Essentially Off
	*/
	public function mod_SecLevel($level = "med", $zone = NULL)
	{
		$this->data['a'] = 'sec_lvl';
		$this->data['z'] = $zone;
		$this->data['v'] = $level;
		
		return $this->retrieve_Data($this->data);
	}
	
	/*
	* Sets the Caching Level to Aggressive or Basic.
	* @access	public
	* @param	string
	* @param	string or NULL
	* @return	json
	*
	* Cache Levels
	*	agg - Aggressive
	*	basic - Basic...duh
	*/
	public function mod_CacheLevel($level = "basic", $zone = NULL)
	{
		$this->data['a'] = 'cache_lvl';
		$this->data['z'] = $zone;
		
		return $this->retrieve_Data($this->data);
	}
	
	/*
	* Allows you to toggle Development Mode on or off for a particular domain. 
	* When Development Mode is on the cache is bypassed. 
	* Development mode remains on for 3 hours or until when it is toggled back off.
	* @access	public
	* @param	boolean integer
	* @param	string or NULL
	* @return	json
	*/
	public function mod_DevMode($switch = 0, $zone = NULL)
	{
		$this->data['a'] = 'devmode';
		$this->data['z'] = $zone;
		$this->data['v'] = $switch;
		
		return $this->retrieve_Data($this->data);
	}
	
	/*
	* Purge CloudFlare of any cached files. It may take up to 48 hours for the cache to rebuild and optimum performance to be achieved so this function should be used sparingly.
	* @access	public
	* @param	string or NULL
	* @return	json
	*/
	public function mod_PurgeCache($zone = NULL)
	{
		$this->data['a'] = 'fpurge_ts';
		$this->data['z'] = $zone;
		$this->data['v'] = 1;

		return $this->retrieve_Data($this->data);
		
	}
	
	/*
	* Tells CloudFlare to take a new image of your site.
	* @access	public
	* @param	integer
	* @return	json
	*/
	public function mod_ZoneGrab($zone_id = NULL)
	{
		if(is_null($zone_id))
		{
			$json = $this->check_Zone();
			$array = json_decode($json, TRUE);
			
			$zone_id = $array[0][0][0];	
		}
		
		$this->data['a'] = 'zone_grab';
		$this->data['zid'] = $zone_id;
		
		return $this->retrieve_Data($this->data);
	}
	
	/*
	* Ban an IP Address
	* @access	public
	* @param	string
	* @return	json
	*/
	public function mod_BlackIp($ip_Address)
	{
		$this->data['a'] = 'ban';
		$this->data['key'] = $ip_Address;
		
		return $this->retrieve_Data($this->data);
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_WhiteIp($ip_Address)
	{
		$this->data['a'] = 'wl';
		$this->data['key'] = $ip_Address;
		
		return $this->retrieve_Data($this->data);	
	}
	
	/*
	* Toggles IPv6 support
	* @access 	public
	* @param	boolean integer
	* @param	string or NULL
	* @return	json
	*/
	public function mod_Ipv6($switch = 0, $zone = NULL)
	{
		$this->data['a'] = 'ipv46';
		$this->data['z'] = $zone;
		$this->data['v'] = $switch;
		
		return $this->retrieve_Data($this->data);
	}

}

