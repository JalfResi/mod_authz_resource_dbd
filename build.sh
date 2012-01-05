
if [ "$OSTYPE" = "linux-gnu" ]; then
{
	sudo apxs2 -c -i -I ./include -I ../authz_resource/include ./src/mod_authz_resource_dbd.c
#	sudo cp ./src/mod_authz_resource_dbd.slo /etc/apache2/mods-available/authz_resource_dbd.load
#	echo "Hello linux"
}
else
{
	if [ "$OSTYPE" = "darwin8.0" ]; then
	{
		sudo apxs -c -i -Wc,-g -I ./include -I ../authz_resource/include ./src/mod_authz_resource_dbd.c
#		sudo cp ./src/mod_authz_resource_dbd.slo /usr/local/apache2/modules/mod_authz_resource_dbd.so
#		echo "OSX DUDE"
	}
	fi
}
fi

~
