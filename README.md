# YourMYOBSupply_Order
Analysis of new Ursnif variant which employs Malicious TLS Callback to achieve Process Injection


# Files, Hashes and URLs

## YourMYOBSupply_Order.zip

* SHA256: 772bc1ae314dcea525789bc7dc5b41f2d4358b755ec221d783ca79b5555f22ce
* VirusTotal: https://www.virustotal.com/#/file/772bc1ae314dcea525789bc7dc5b41f2d4358b755ec221d783ca79b5555f22ce/detection

## Your_MYOB_Supply_Order.js

* SHA256: 9f7413a57595ffe33ca320df26231d30a521596ef47fb3e3ed54af1a95609132
* VirusTotal: https://www.virustotal.com/#/file/9f7413a57595ffe33ca320df26231d30a521596ef47fb3e3ed54af1a95609132/detection

## clients.7z

* SHA256: e498b56833da8c0170ffba4b8bcd04f85b99f9c892e20712d6c8e3ff711fa66c
* VirusTotal: https://www.virustotal.com/#/file/e498b56833da8c0170ffba4b8bcd04f85b99f9c892e20712d6c8e3ff711fa66c/detection


# Behaviour

Malware starts with zip file <a href="./YourMYOBSupply_Order.zip">YourMYOBSupply_Order.zip</a>, so we had to unzip in our desktop for example.
Inside of the output folder, we've found a file dubbed YourMYOBSupply_Order.js as you can see in <a href="./Your_MYOB_Supply_Order.js">Your_MYOB_Supply_Order.js</a>
this javascript file is ofuscated with variables rename technique, and string ciphered method, it uses this method to decipher:

```Javascript
function String.prototype.dva(){ var u0zUnq='';
var qRatq1N='F';var R8pAJyZI=N89mpis97-hyYhDTXbWVs;var JqGGXMMv9=this.split(u0zUnq);var JNBVcUPJxh='0';jPAzrTcHGv=vuja(JqGGXMMv9);YHg6e5lbOG=u0zUnq; if(BCHXYwu[(4-1)+jPAzrTcHGv].length==8/2){var RuVFYb=YHg6e5lbOG;for(var i=0;i<jPAzrTcHGv/6;i++) { YHg6e5lbOG=JqGGXMMv9[i];if ((YHg6e5lbOG<=qRatq1N)&&(YHg6e5lbOG>=JNBVcUPJxh)) { if (((((0x755096e>>0x20)*(0x231238856f4a6800/0x231238856f4a6800)+(0x155ed24>>1))>>>(0x1b<<32))+RuVFYb.length)>(4/4)) {IxdhAELZKon=fule(RuVFYb+YHg6e5lbOG); RuVFYb='';u0zUnq=u0zUnq+kigy(IxdhAELZKon);} else { RuVFYb=YHg6e5lbOG; } } } } return u0zUnq; }
```

If we deofuscate this method, we have something like this:

```Javascript
function String.prototype.dva()
{ 
	var u0zUnq='';

	var qRatq1N='F';
	var R8pAJyZI=N89mpis97-hyYhDTXbWVs;
	var JqGGXMMv9=this.split(u0zUnq);
	var JNBVcUPJxh='0';
	jPAzrTcHGv=func_retorna_length_2_3(JqGGXMMv9);
	YHg6e5lbOG=u0zUnq;
	 if(BCHXYwu[(4-1)+jPAzrTcHGv].length==8/2){
		var RuVFYb=YHg6e5lbOG;
			for(var i=0;i<jPAzrTcHGv/6;i++) { 
			YHg6e5lbOG=JqGGXMMv9[i];
				if ((YHg6e5lbOG<=qRatq1N)&&(YHg6e5lbOG>=JNBVcUPJxh)) { 
					if ((((123013486*1+11204242)>>>27)+RuVFYb.length)>1) {
						IxdhAELZKon=func_retorna_num_base_16(RuVFYb+YHg6e5lbOG);
						RuVFYb='';
						u0zUnq=u0zUnq+return_char_from_int(IxdhAELZKon);
					} else { 
						RuVFYb=YHg6e5lbOG;
					} 
				} 
			} 
		} 
	return u0zUnq;
}
```

The behaviour of the javascript is to connect with one of three servers to download a 7zip file, really this 7zip file is an executable MZ, as we can see here:

```Javascript
if (ycz4qOT&&ycz4qOT=="OK") { 
	if (IsESHwrjqQe8<1) {
		var response_server = pyuU9XIy["responseText"];

		var P4eTJ3 = response_server.split('');
		if (P4eTJ3[0]+P4eTJ3[1]=="MZ") { 
			flag=1;
		} 
	}
	else { 
		flag=1;
	 } 
} 
```

It's checking if the first two bytes of the header have the letters 'M' and 'Z' from the executable header of Microsoft.