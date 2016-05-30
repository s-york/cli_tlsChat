#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <tls.h>

//error messages
#define CA_ERROR "Seems the public or private key is missing. Make sure to generate \
				  these with the openssl command. Learn how by running \"man openssl\" in \
				  your terminal or reading the provided documentation. These files need \
				  to be name \"spookIO_serv_KEY.pem\" for the public and \"spookIO_serv_CA.pem\" \
				  for the private cert.\n" 
//setting 
#define SECPATH "sec/"
#define SECPPATH "sec/pub/" //permissions  ?
#define servKEY "spookIO_serv_KEY.pem"
#define servCA "spookIO_serv_CA.pem"

//get server key=========================================key
int8_t TLS_Init_Secrets(struct tls_config *config){
	//remember to test return for error
	int8_t er=0;
		if((er = tls_init())<0){
			perror("ERROR:");
			fprintf(stderr,"TLS init failed: %d",er);exit(-1);}
//private cert name
	if((er = tls_config_set_ca_file(config, servCA))==-1){
			perror("ERROR:");
			fprintf(stderr,CA_ERROR);
		return(er);
	}
//where to look for private key	
	if((er = tls_config_set_ca_path(config, SECPATH))==-1){
			perror("ERROR:");
			fprintf(stderr,"Failed to set ca path.\n");
		return(er);
	}
//public key
	if((er = tls_config_set_cert_file(config, servKEY))==-1){
			perror("ERROR:");
			fprintf(stderr,CA_ERROR);
		return(er);
	}
//where to look for servKEY public
	if((er = tls_config_set_ca_path(config, SECPPATH))==-1){
			perror("ERROR:");
			fprintf(stderr,"Failed to set public path.\n");
		return(er);
	}
//we made it through
return(1);
}
//configure server for encryption========================serv
int8_t TLS_Config_Server(struct tls *ctx){
		int err=0; 
//init TLS structs.
	if((err = tls_init())<0){
		fprintf(stderr,"TLS init failed: %d",err);exit(-1);}
	if((ctx = tls_server())==NULL){
		fprintf(stderr,"TLS init failed: %d",err);exit(-1);}
//config
	struct tls_config *enConfig;
//return a fresh TLS config object.
	if ((enConfig = tls_config_new()) < 0){
		fprintf(stderr, "default tls config failed: ERROR \"%d\"",errno);
		exit(-1);
	}
//setup our config options ========CONFIGS
	if((err = TLS_Init_Secrets(enConfig)) == -1){
		exit(-1);
	}
	tls_config_set_ciphers(enConfig, "secure");

	tls_config_prefer_ciphers_server(enConfig);

	tls_config_set_protocols(enConfig, TLS_PROTOCOLS_DEFAULT);
//setup our config options ========CONFIGS

//bind our config object to our ctx
	if((tls_configure(ctx, enConfig))==-1){
		tls_error(ctx);
	}
return(1);
}