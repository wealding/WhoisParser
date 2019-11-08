<?php

namespace Whoisdoma\WhoisParser\Templates;

use Whoisdoma\WhoisParser\Templates\Type\Regex;


class Ir extends Regex
{

    /**
	 * Blocks within the raw output of the whois
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blocks = array(1 => '/domain:(?>[\x20\t]*)(.*?)(?=source)/is', 
            2 => '/nic-hdl:(?>[\x20\t]*)(.*?)(?=source)/is');

    /**
	 * Items for each block
	 * 
	 * @var array
	 * @access protected
	 */
    protected $blockItems = array(
            1 => array('/nserver:(?>[\x20\t]*)(.*?)<br/im' => 'nameserver',
                    '/last-updated:(?>[\x20\t]*)(.*?)<br/im' => 'changed',
                    '/expire-date:(?>[\x20\t]*)(.*?)<br/im' => 'expires',
                    '/holder-c:(?>[\x20\t]*)(.*?)<br/im' => 'network:contacts:owner',
                    '/admin-c:(?>[\x20\t]*)(.*?)<br/im' => 'network:contacts:admin',
                    '/tech-c:(?>[\x20\t]*)(.*?)<br/im' => 'network:contacts:tech'),
            
            2 => array('/nic-hdl:(?>[\x20\t]*)(.*?)<br/im' => 'contacts:owner:handle',
                    '/org:(?>[\x20\t]*)(.*?)<br/im' => 'contacts:owner:organization',
                    '/e-mail:(?>[\x20\t]*)(.*?)<br/im' => 'contacts:owner:email',
                    '/address:(?>[\x20\t]*)(.*?)<br/im' => 'contacts:owner:address',
                    '/phone:(?>[\x20\t]*)(.*?)<br/im' => 'contacts:owner:phone',
                    '/fax-no:(?>[\x20\t]*)(.*?)<br/im' => 'contacts:owner:fax'));

    /**
     * RegEx to check availability of the domain name
     *
     * @var string
     * @access protected
     */
    protected $available = '/no entries found/i';


    public function postProcess(&$WhoisParser)
    {
        $ResultSet = $WhoisParser->getResult();
        if ($ResultSet->created == null) {
            $ResultSet->created = $ResultSet->changed;
        }
    }
}