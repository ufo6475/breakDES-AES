#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

int base64Len(const char* input){
	int len=strlen(input);
	int padding =0;
	if(input[len-1]=='='&&input[len-2]=='='){
		padding=2;
}
	else if(input[len-1]=='=')
		padding=1;
	else
		padding=0;

	return (int)len*0.75-padding;

}


int Base64Decode(char* msg,char** buffer){

	BIO *bio,*b64;
	int decodelen=base64Len(msg);
	int len=0;
	*buffer=(char*)malloc(decodelen+1);

	
	FILE *str = fmemopen(msg,strlen(msg),"r");
	b64=BIO_new(BIO_f_base64());
	bio=BIO_new_fp(str,BIO_NOCLOSE);
	bio=BIO_push(b64,bio);
	BIO_set_flags(bio,BIO_FLAGS_BASE64_NO_NL);
	len=BIO_read(bio,*buffer,strlen(msg));
	(*buffer)[len]='\0';
	BIO_free_all(bio);
	fclose(str);
	return 0;

}

typedef struct _dp_struct{
	long long value;
	int index;
}DP_struct;



int compare(const void*a, const void *b){
	DP_struct a1=*(DP_struct*)a;
	DP_struct a2=*(DP_struct*)b;
	if(a1.value<a2.value)
		return -1;
	if(a2.value<a1.value)
		return 1;
	return 0;
}

int bn_search(long long tmp,DP_struct* DP,int start,int mid,int end){
	
	if(tmp==DP[mid].value)
		return DP[mid].index;
	if(start>mid||mid>=end)
		return -1;


	if(tmp<=DP[mid].value){
		return bn_search(tmp,DP,start,(start+mid)/2,mid);
}
	else{
		return bn_search(tmp,DP,mid+1,(mid+1+end)/2,end);
		}

}


int main(){


	clock_t st1=clock();
	FILE *inputFP=NULL;
	char *Plain;
	char *Cypertmp;
	char *Cyper;
	char *pLine;
	off_t ps=0;
	long long size;


	//Get plaintext and ciphertext
	if((inputFP=fopen("./PlaintextCiphertext.txt","r"))==NULL)
		perror("Failed to open file");

	fseek(inputFP,0,SEEK_END);
	size=ftell(inputFP);
	Plain=malloc(size+1);
	memset(Plain,0,size+1);
	Cypertmp=malloc(size+1);
	memset(Cypertmp,0,size+1);
	Cyper=malloc(size+1);
	memset(Cyper,0,size+1);
	fseek(inputFP,0,SEEK_SET);


	pLine = fgets(Plain,size,inputFP);
	fread(Cypertmp,sizeof(char),size,inputFP);

	char* tmp;

	//Decoding ciphertext
	Base64Decode(Cypertmp,&tmp);
	strcpy(Cyper,tmp);
	fclose(inputFP);


	FILE *pwFP=NULL;
	if((pwFP=fopen("./password.txt","r"))==NULL)
		perror("Failed to open file");


	DP_struct DP[184389];
	char *password[184389];
	int tt=0;
	char line[1024];

	//Decrypt the cyphertext
	while(!feof(pwFP)){
		memset(line,0,1024);
		pLine=fgets(line,1024,pwFP);
		char * tkn=strtok(pLine," ");
		unsigned char KEY2[8];
		for(int i=0;i<16;i++){
			char tmp1=isdigit(tkn[2*i])?tkn[2*i]-'0':tkn[2*i]-'a'+10;
			char tmp2=isdigit(tkn[2*i+1])?tkn[2*i+1]-'0':tkn[2*i+1]-'a'+10;
			KEY2[i]=(tmp1<<4)+tmp2;
		}
		unsigned int message_len=strlen((char*)Cyper)+1;
		unsigned encrypt_len=(message_len%AES_BLOCK_SIZE==0)?message_len:(message_len/AES_BLOCK_SIZE+1)*AES_BLOCK_SIZE;
		AES_KEY aeskey;
		int ret=AES_set_decrypt_key(KEY2,128,&aeskey);
		if(ret<0)
			perror("AES encrypt error");
		unsigned char iv[AES_BLOCK_SIZE];
		memset(iv,0,AES_BLOCK_SIZE);
		unsigned char *output=(unsigned char*)malloc(sizeof(char)*encrypt_len);
		AES_cbc_encrypt((const unsigned char*)Cyper,output,encrypt_len,&aeskey,iv,AES_DECRYPT);
	
		long long rem=0;
		for(int i=0;i<6;i++){
			rem=rem<<8;
			rem+=output[i];
		}
		DP[tt].value=rem;
		DP[tt].index=tt;	
		tkn=strtok(NULL," ");
		password[tt]=(char*)malloc(sizeof(char)*30);	
		strcpy(password[tt],tkn);
		if(tt==184388){
			strcat(password[tt],"\n");
}
		tt++;
		

	}
	fclose(pwFP);

	qsort(DP,sizeof(DP)/sizeof(DP_struct),sizeof(DP_struct),compare);

	tt=0;
	if((pwFP=fopen("./password.txt","r"))==NULL)
		perror("Failed to open file");

	//Encrypt the plaintext
	while(!feof(pwFP)){
		memset(line,0,1024);
		pLine=fgets(line,1024,pwFP);
		char * tkn=strtok(pLine," ");
		unsigned char KEY1[8];
		for(int i=0;i<8;i++){
			char tmp1=isdigit(tkn[2*i])?tkn[2*i]-'0':tkn[2*i]-'a'+10;
			char tmp2=isdigit(tkn[2*i+1])?tkn[2*i+1]-'0':tkn[2*i+1]-'a'+10;
			KEY1[i]=(tmp1<<4)+tmp2;
		}
		
		DES_cblock key;
		DES_key_schedule schedule;
		
		for(int i=0;i<8;i++){
			key[i]=KEY1[i];
		}
		DES_set_key(&key,&schedule);
		const int decrypt_len=strlen(Plain);		
		unsigned char IN[decrypt_len];
		for(int i=0;i<decrypt_len;i++){
			IN[i]=Plain[i];
		}

					
		unsigned char OUT[decrypt_len];
		memset(OUT,0,decrypt_len);
		
		DES_ecb_encrypt(&IN,&OUT,&schedule,DES_ENCRYPT);


		long long ret=0;
		for(int i=0;i<6;i++){
			ret=ret<<8;
			ret+=OUT[i];
		}
		int result=bn_search(ret,DP,0,184388/2,184388);

		if(result!=-1){
			FILE* outFP= fopen("./keys.txt","w");
			fprintf(outFP,"%s%s",password[tt],password[result]);
			fclose(outFP);
			break;
		}
		
		tt++;
	}


	for(int i=0;i<184388;i++)
		free(password[i]);


	free(Plain);
	free(Cyper);
	free(Cypertmp);
	fclose(pwFP);


}
