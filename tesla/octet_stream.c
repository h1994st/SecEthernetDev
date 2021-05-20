#include "octet_stream.h"
#ifdef WIN32
#include <winsock.h>
#else
#include <netinet/in.h>
#endif

const static int32 ZERO=0x00000000;

//copies len bytes from s2 to s1
//if len is not an integer multiple of OCTET_PADDING
//then the buffer is padded to fill the space
//if s2 is NULL, no data is copied, but the padding is done
//the final position of the pointer is returned
octet_stream make_octet(void *buf){
  octet_stream str;
  str.cbuff=buf;
  str.pos=0;
  return str;
}

TESLA_ERR octetEVPSign(octet_stream *str,EVP_MD_CTX *ctx,EVP_PKEY *pkey,int16 slen){
  int s=0;
  char *sig=NULL;
  sig=malloc(slen);
  if(!sig) return TESLA_ERR_NO_MEMORY;
  EVP_SignFinal(ctx,sig,&s,pkey);
  //2 byte int for the length
  octet_wint16(str,(int16 *)&s);
  octetwrt(str,sig,s);
  free(sig);
  s=slen-s;
  octetwrt(str,&ZERO,(s % sizeof(int32)));
  s-=(s % sizeof(int32));
  while(s>0){
    octetwrt(str,&ZERO,sizeof(int32));
    s-=sizeof(int32);
  }
  return TESLA_OK;
}

TESLA_ERR octetEVPread(octet_stream *str,EVP_MD_CTX *ctx,EVP_PKEY *pkey,int16 slen){
  int16 s=0;
  int ret=0;
  octet_rint16(str,&s);
  ret=EVP_VerifyFinal(ctx,str->cbuff,s,pkey);
  str->cbuff+=s;
  str->pos+=s;
  //if we expected more than s bytes, skip the rest
  octet_skip(str,slen-s);
  if(ret==-1)
    return TESLA_ERR_BAD_SIGNATURE;
  else if( ret==0)
    return TESLA_ERR_INVALID_SIGNATURE;
  else
    return TESLA_OK;
}


void octetwrt(octet_stream *str,void const *s2,int len){
  if(s2!=NULL){
    memcpy(str->cbuff,s2,len);
  }
  str->pos+=len;
  str->cbuff+=len;
}

void octetrd(octet_stream *str,void *out,int len){
  memcpy(out,str->cbuff,len);
  str->cbuff+=len;
  str->pos+=len;
}

void wpad(octet_stream *str){
  if(str->pos % OCTET_SIZE >0){
    memcpy(str->cbuff,&ZERO,OCTET_SIZE - (str->pos % OCTET_SIZE));
    str->cbuff+=OCTET_SIZE - (str->pos % OCTET_SIZE);
    str->pos+=OCTET_SIZE - (str->pos % OCTET_SIZE);
  }
}

void rpad(octet_stream *str){
  if(str->pos % OCTET_SIZE >0){
    str->cbuff+=OCTET_SIZE - (str->pos % OCTET_SIZE);
    str->pos+=OCTET_SIZE - (str->pos % OCTET_SIZE);
  }
}

void wNTP(octet_stream *str,NTP_t *a){
  NTP_write(str->cbuff,a);
  str->cbuff+=NTP_SIZE;
  str->pos+=NTP_SIZE;
}

void rNTP(octet_stream *str,NTP_t *a){
  NTP_read(str->cbuff,a);
  str->cbuff+=NTP_SIZE;
  str->pos+=NTP_SIZE;
}

#ifdef WORDS_BIGENDIAN
//nothing to do, macros were defined in tesla.h
#else
//have to convert to/from network order
inline void octet_wint16(octet_stream *str,int16 *k){
  int16 val=htons(*k);
  octetwrt(str,&val,sizeof(int16));
}
inline void octet_rint16(octet_stream *str,int16 *k){
  octetrd(str,k,sizeof(int16));
  *k=ntohs(*k);
}
inline void octet_wint32(octet_stream *str,int32 *k){
  int32 val=htonl(*k);
  octetwrt(str,&val,sizeof(int32));
}
inline void octet_rint32(octet_stream *str,int32 *k){
  octetrd(str,k,sizeof(int32));
  *k=ntohl(*k);
}
inline void octet_wint64(octet_stream *str,int64 *k){
  int32 Upper=*(int32 *)k;
  int32 Lower=*(((int32 *)k)+1);
  Upper=htonl(Upper);
  Lower=htonl(Lower);
  octetwrt(str,&Lower,sizeof(int32));
  octetwrt(str,&Upper,sizeof(int32));
}
inline void octet_rint64(octet_stream *str,int64 *k){
  int32 temp;
  octetrd(str,k,sizeof(int64));
  temp=ntohl(*(int32 *)k);
  *(int32 *)k=ntohl(*((int32 *)k + 1));
  *((int32 *)k + 1)=temp;
}
#endif
