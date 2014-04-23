#!/bin/sh
openssl=`which openssl`
days="1500"
certversion="3"

#   WE ARE CALLED FROM THE PARENT DIR!
sslcrtdir="conf/ssl.crt"
sslcsrdir="conf/ssl.csr"
sslkeydir="conf/ssl.key"

mkdir -p $sslcrtdir
mkdir -p $sslcsrdir
mkdir -p $sslkeydir

randfiles=''
for file in /var/log/messages /var/run/dmesg.boot /var/log/system.log /var/wtmp \
            /kernel /boot/vnlinuz /etc/hosts /etc/group /etc/resolv.conf \
            /bin/ls; do
    if [ -r $file ]; then
        if [ ".$randfiles" = . ]; then
            randfiles="$file"
        else
            randfiles="${randfiles}:$file"
        fi
    fi
done

echo "STEP1: Generating RSA private key for CA (1024 bit) [ca.key]"
	if [ ".$randfiles" != . ]; then
		$openssl genrsa -rand $randfiles -out $sslkeydir/ca.key 1024
	else
		$openssl genrsa -out $sslkeydir/ca.key 1024
	fi
	if [ $? -ne 0 ]; then
		echo "mkcert.sh:Error: Failed to generate RSA private key" 1>&2
		exit 1
	fi

echo " "
echo "______________________________________________________________________"
echo "STEP 2: Generating X.509 certificate signing request for CA [ca.csr]"
	cat >.mkcert.cfg <<EOT
[ req ]
default_bits                    = 1024
distinguished_name              = req_DN
[ req_DN ]
countryName                     = "1. Country Name             (2 letter code)"
countryName_default             = XY
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = "2. State or Province Name   (full name)    "
stateOrProvinceName_default     = Snake Desert
localityName                    = "3. Locality Name            (eg, city)     "
localityName_default            = Snake Town
0.organizationName              = "4. Organization Name        (eg, company)  "
0.organizationName_default      = Snake Oil, Ltd
organizationalUnitName          = "5. Organizational Unit Name (eg, section)  "
organizationalUnitName_default  = Certificate Authority
commonName                      = "6. Common Name              (eg, CA name)  "
commonName_max                  = 64
commonName_default              = Snake Oil CA
emailAddress                    = "7. Email Address            (eg, name@FQDN)"
emailAddress_max                = 40
emailAddress_default            = ca@snakeoil.dom
EOT
	$openssl req -config .mkcert.cfg \
		-new -key $sslkeydir/ca.key \
		-out $sslcsrdir/ca.csr 
	if [ $? -ne 0 ]; then
		echo "mkcert.sh:Error: Failed to generate certificate signing request" 1>&2
		exit 1
	fi
	rm -f .mkcert.cfg
echo " "
echo "______________________________________________________________________"
echo "STEP 3: Generating X.509 certificate for CA signed by itself [ca.crt]"

	if [ ".$certversion" = .3 -o ".$certversion" = . ]; then
		extfile="-extfile .mkcert.cfg"
		cat >.mkcert.cfg <<EOT
extensions = x509v3
[ x509v3 ]
subjectAltName   = email:copy
basicConstraints = CA:true,pathlen:0
nsComment        = "mod_ssl generated custom CA certificate"
nsCertType       = sslCA
EOT
	fi
	$openssl x509 $extfile -days $days \
                      -signkey $sslkeydir/ca.key \
                      -in      $sslcsrdir/ca.csr -req \
                      -out     $sslcrtdir/ca.crt
                      
	if [ $? -ne 0 ]; then
		echo "mkcert.sh:Error: Failed to generate X.509 certificate" 1>&2
		exit 1
	fi
	rm -f .mkcert.cfg
	
	echo "Verify: matching certificate & key modulus"
		modcrt=`$openssl x509 -noout -modulus -in $sslcrtdir/ca.crt | sed -e 's;.*Modulus=;;'`
		modkey=`$openssl rsa -noout -modulus -in $sslkeydir/ca.key | sed -e 's;.*Modulus=;;'`
		if [ ".$modcrt" != ".$modkey" ]; then
			echo "mkcert.sh:Error: Failed to verify modulus on resulting X.509 certificate" 1>&2
			exit 1
		fi
        
	echo "Verify: matching certificate signature"
		$openssl verify $sslcrtdir/ca.crt
		if [ $? -ne 0 ]; then
			echo "mkcert.sh:Error: Failed to verify signature on resulting X.509 certificate" 1>&2
			exit 1
		fi
		
echo " "
echo "______________________________________________________________________"
echo "STEP 4: Generating $algo private key for SERVER (1024 bit) [server.key]"
	if [ ".$randfiles" != . ]; then
		$openssl genrsa -rand $randfiles -out $sslkeydir/server.key 1024
	else
		$openssl genrsa -out $sslkeydir/server.key 1024
	fi
	if [ $? -ne 0 ]; then
		echo "mkcert.sh:Error: Failed to generate RSA private key" 1>&2
		exit 1
	fi

echo " "
echo "______________________________________________________________________"
echo "STEP 5: Generating X.509 certificate signing request for SERVER [server.csr]"
	cat >.mkcert.cfg <<EOT
[ req ]
default_bits                    = 1024
distinguished_name              = req_DN
[ req_DN ]
countryName                     = "1. Country Name             (2 letter code)"
countryName_default             = XY
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = "2. State or Province Name   (full name)    "
stateOrProvinceName_default     = Snake Desert
localityName                    = "3. Locality Name            (eg, city)     "
localityName_default            = Snake Town
0.organizationName              = "4. Organization Name        (eg, company)  "
0.organizationName_default      = Snake Oil, Ltd
organizationalUnitName          = "5. Organizational Unit Name (eg, section)  "
organizationalUnitName_default  = FTP Team
commonName                      = "6. Common Name              (eg, FQDN)     "
commonName_max                  = 64
commonName_default              = ftp.snakeoil.dom
emailAddress                    = "7. Email Address            (eg, name@fqdn)"
emailAddress_max                = 40
emailAddress_default            = ftp@snakeoil.dom
EOT

	$openssl req -config .mkcert.cfg -new \
		-key $sslkeydir/server.key \
		-out $sslcsrdir/server.csr
	if [ $? -ne 0 ]; then
		echo "mkcert.sh:Error: Failed to generate certificate signing request" 1>&2
		exit 1
	fi
	rm -f .mkcert.cfg
	
echo " "
echo "______________________________________________________________________"
echo "STEP 6: Generating X.509 certificate signed by own CA [server.crt]"
	extfile=""
	if [ ".$certversion" = .3 -o ".$certversion" = . ]; then
		extfile="-extfile .mkcert.cfg"
		cat >.mkcert.cfg <<EOT
extensions = x509v3
[ x509v3 ]
subjectAltName   = email:copy
nsComment        = "mod_ssl generated custom server certificate"
nsCertType       = server
EOT
	fi
	if [ ! -f .mkcert.serial ]; then
		echo '01' >.mkcert.serial
	fi
	$openssl x509 $extfile \
		-days $days \
		-CAserial .mkcert.serial \
		-CA    $sslcrtdir/ca.crt \
		-CAkey $sslkeydir/ca.key \
		-in    $sslcsrdir/server.csr -req \
		-out   $sslcrtdir/server.crt
	if [ $? -ne 0 ]; then
		echo "mkcert.sh:Error: Failed to generate X.509 certificate" 1>&2
		exit 1
	fi
	rm -f .mkcert.cfg
	
	echo "Verify: matching certificate & key modulus"
		modcrt=`$openssl x509 -noout -modulus -in $sslcrtdir/server.crt | sed -e 's;.*Modulus=;;'`
		modkey=`$openssl rsa -noout -modulus -in $sslkeydir/server.key | sed -e 's;.*Modulus=;;'`
        if [ ".$modcrt" != ".$modkey" ]; then
            echo "mkcert.sh:Error: Failed to verify modulus on resulting X.509 certificate" 1>&2
            exit 1
        fi

	echo "Verify: matching certificate signature"
	$openssl verify -CAfile $sslcrtdir/ca.crt $sslcrtdir/server.crt
	if [ $? -ne 0 ]; then
		echo "mkcert.sh:Error: Failed to verify signature on resulting X.509 certificate" 1>&2
		exit 1
	fi

echo "______________________________________________________________________"
echo ""

chmod 755 $sslcrtdir
chmod 755 $sslcsrdir
chmod 700 $sslkeydir

chmod 400 $sslcrtdir/*
chmod 400 $sslcsrdir/*
chmod 400 $sslkeydir/*
