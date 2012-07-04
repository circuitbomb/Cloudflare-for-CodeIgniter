<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/**
 * Cloudflare Client Interface API Library
 *
 * @package		CodeIgniter
 * @subpackage	Libraries
 * @category	APIs/Cloudflare
 * @author		Dustin Blake (Circuitbomb)
 * @link		http://example.com
 */

class Cloudflare {

	private $api_Url = "https://www.cloudflare.com/api_json.html?";		//Request URL
	private $log_Path = "assets/apis/cloudflare/";						//Path to log requests with ending backslash
	private $token = "fbf5e59e37b399483255dc9a7454c6c57071a";			//Cloudflare API key
	private $email = "circuitbomb.db@gmail.com";						//Associated Email address
	private $default_Zone = "vilelabs.net";                           	//Default Zone
	
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
		
		$fp = fopen($this->logpath . "cloudflare_".$array['a']."-".date("Y-m-d").".txt", "a");
		
		curl_setopt($init, CURLOPT_URL, $this->direction);
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
		
		$do_action = $this->retrieve_Data($this->data);
			
		return $do_action;
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
		
		$do_action = $this->retrieve_Data($this->data);
		
		return $do_action;
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
			
		$do_action = $this->retrieve_Data($this->data);

		return $do_action;
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
		
		$do_action = $this->retrieve_Data($this->data);
		
		return $do_action;
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
		
		$do_action = $this->retrieve_Data($this->data);
		
		return $do_action;
	
	}
	
	/*
	* Find the current threat score for a given IP. Note that scores are on a logarithmic scale, where a higher score indicates a higher threat.
	* @access	public
	* @param	string
	* @return	json
	*/
	public function get_IpsScore($ip_address = "0.0.0.0")
	{
		$this->data['a'] = 'ip_lkup';
		$this->data['ip'] = $ip_address;
		
		$do_action = $this->retrieve_Data($this->data);
		
		return $do_action;
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_SecLevel($zone = NULL, $level = "eoff")
	{
		
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_CacheLevel($zone = NULL, $level = "basic")
	{
		
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_DevMode($zone = NULL, $switch = "off")
	{
		
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_PurgeCache($zone = NULL)
	{
		
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_ZoneGrab($zone_id = NULL)
	{
		
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_BlackIp($ip_address = NULL)
	{
		
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_WhiteIp($ip_address = NULL)
	{
		
	}
	
	/*
	* 
	* @access
	* @param
	* @return
	*/
	public function mod_Ipv6($zone = NULL, $switch = 0)
	{
		
	}

}

