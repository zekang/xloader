<?php
class XLoaderUtil
{
	private $secretKey;

	public function __construct($secretKey)
	{
		$this->secretKey = $secretKey;
	}

    /**
     * @param null $mac
     * @param int $expire
     * @param string $hwname
     * @return mixed
     */
    public function getLicence($mac=null,$expire=0,$hwname='eth0')
	{
		if($mac === null){
			$mac = $this->getMacAddress($hwname);
		}
		return xloader_license($this->secretKey,$mac,$expire,$hwname);
	}

    /**
     * @param string $hwname
     * @return mixed
     */
    public function getMacAddress($hwname='eth0')
	{
		return  xloader_hardware_address($hwname);
	}

    /**
     * @param null $mac
     * @param int $expire
     * @param string $hwname
     * @return string
     */
    public function getConfigValue($mac=null,$expire=0,$hwname='eth0')
	{
		$config = $this->getLicence($mac,$expire,$hwname);
		$template = <<< EOD
[xloader]
extension=xloader.so
xloader.license_path="%s"
xloader.license_sign="%s"
xloader.cache_enable=1

EOD;
		return sprintf($template,$config['license'],$config['license_sign']);
	}

    /**
     * @param $sourceDir
     * @param $targetDir
     */
    public function encryptFiles($sourceDir,$targetDir)
	{
		if(is_dir($sourceDir)){
				$handler = opendir($sourceDir);
				while($file = readdir($handler)){
						if($file == '.' || $file == '..'){
								continue;
						}
						if(is_dir($sourceDir.'/'.$file)){
								$this->encryptFiles($sourceDir.'/'.$file,$targetDir.'/'.$file);
						}else{
								$this->encryptFiles($sourceDir.'/'.$file,$targetDir);
						}
				}
		}else{
				if(!file_exists($targetDir)){
					mkdir($targetDir,0755,true);
				}
				if(strtolower(pathinfo($sourceDir,PATHINFO_EXTENSION))== 'php'){
						xloader_encrypt($this->secretKey,$sourceDir,$targetDir);
						echo 'encrypt file:'.$sourceDir.PHP_EOL;
				}else{
						$filename = basename($sourceDir);
						copy($sourceDir,$targetDir.'/'.$filename);
				}
		}
	}
}
$key = "123342342";
$xloaderUtil = new XLoaderUtil($key);
//$xloaderUtil->encryptFiles('/data/wwwroot/demo','/data/wwwroot/new');
//echo $xloaderUtil->getConfigValue(null,0,'eth1');
//echo $xloaderUtil->getMacAddress('eth1').PHP_EOL;
$config = $xloaderUtil->getLicence(null,0,'eth1');
print_r($config);