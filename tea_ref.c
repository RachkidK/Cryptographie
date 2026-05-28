#include <stdint.h>
#include <stdio.h>
void encrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

int main(){
    uint32_t k[4];
    uint32_t v[2];
    
    //Key
    k[0] = 0b01110100011110101010010010010010;
    k[1] = 0b11110000101010100011010101101000;
    k[2] = 0b00100010111010010111010110110011;
    k[3] = 0b00001010110111010110100110100011;
    
    //Plaintext (1 block)
    v[0] = 0b01010101010101010101010101010101;
    v[1] = 0b11111111111111110000000000000000;
    
    printf("Plaintext:\n");
    printf("%u\n",v[0]);
    printf("%u\n",v[1]);
    
    encrypt(v,k);
    
    printf("Ciphertext:\n");
    printf("%u\n",v[0]);
    printf("%u\n",v[1]);
    
    decrypt(v,k);
    
    printf("Decryption:\n");
    printf("%u\n",v[0]);
    printf("%u\n",v[1]);

    return 0;
}
