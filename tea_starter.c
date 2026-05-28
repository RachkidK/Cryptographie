#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint32_t F(uint32_t v, const uint32_t k[4], int i) {
    return ((v << 4) + k[2 * (i % 2)]) ^ (v + (0x9E3779B9 * ((i + 2) / 2))) ^ ((v >> 5) + k[1 + 2 * (i % 2)]); 
}

void feistel_enc(uint32_t v[2], const uint32_t k[4]) {
    //TODO
    int i = 0;
    while(i < 64) {

        // Calcul
        uint32_t tmp = v[1];
        uint32_t f = F(v[1], k, i);
        uint32_t r = v[0] + f; 

        // Mise a jour de v
        v[0] = tmp;
        v[1] = r;

        // On incremente
        i++;
    }
}



void feistel_dec(uint32_t v[2], const uint32_t k[4]) {
    //TODO
    int i = 63;

    while(i >= 0){
        uint32_t tmp = v[0];
        uint32_t f = F(tmp, k, i);
        uint32_t r = v[1] - f;

        // Mise a jour
        v[0] = r;
        v[1] = tmp;

        i--;
    }

}
 

void ecb_encrypt(uint32_t *v, const uint32_t k[4], int nb_blocks) {
    //TODO
    int i = 0;
    while(i<nb_blocks){
        
        int j = 2*i;

        uint32_t tmp[2];
        tmp[0] = v[j];
        tmp[1] = v[j+1];

        feistel_enc(tmp, k);

        v[j] = tmp[0];
        v[j+1] = tmp[1];

        i++;
    }

}



void ecb_decrypt(uint32_t * v, const uint32_t k[4], int nb_blocks) {
    //TODO
    int i = 0;
    while(i<nb_blocks){
        
        int j = 2*i;

        uint32_t tmp[2];
        tmp[0] = v[j];
        tmp[1] = v[j+1];

        feistel_dec(tmp, k);

        v[j] = tmp[0];
        v[j+1] = tmp[1];

        i++;
    }
}



void cbc_encrypt(uint32_t * v, uint32_t vect[2], const uint32_t k[4], int nb_blocks) {
    //TODO
    int i = 0;
    while (i < nb_blocks)
    {
        int j = 2*i;

        // Formation du bloc 64 bits
        uint32_t tmp[2];
        tmp[0] = v[j];
        tmp[1] = v[j+1];
        
        // Addition avec le vecteur (xor)
        tmp[0] ^= vect[0];
        tmp[1] ^= vect[1];

        // Cryptage
        feistel_enc(tmp, k);

        v[j] = tmp[0];
        v[j+1] = tmp[1];

        // Mise a jour
        vect[0] = tmp[0];
        vect[1] = tmp[1];

        i++;
    }
    
}

void cbc_decrypt(uint32_t * v, uint32_t vect[2], const uint32_t k[4], int nb_blocks) {
    //TODO
    int i = 0;
    while (i < nb_blocks)
    {
        int j = 2*i;
        // Formation du bloc 64 bits

        uint32_t cipher[2];
        cipher[0] = v[j];
        cipher[1] = v[j+1];


        uint32_t tmp[2];
        tmp[0] = cipher[0];
        tmp[1] = cipher[1];

        // Decryptage
        feistel_dec(tmp, k);
        
        // soustraction avec le vecteur
        tmp[0] ^= vect[0];
        tmp[1] ^= vect[1];

        v[j] = tmp[0];
        v[j+1] = tmp[1];

        // Mise a jour
        vect[0] = cipher[0];
        vect[1] = cipher[1];

        i++;
    }
    
}

void ofb_stream(uint32_t* stream, uint32_t vect[2], const uint32_t k[4], int nb_blocks) {
    //TODO
    int i = 0;
    while (i < nb_blocks)
    {
        feistel_enc(vect, k);

        int j = 2*i;
        stream[j] = vect[0];
        stream[j+1] = vect[1];

        i++;

    }
    
}

void ofb_encrypt(uint32_t * v, uint32_t * stream, int nb_blocks) {
    //TODO
    int i = 0;
    while (i < nb_blocks)
    {
        int j = 2*i;
        v[j] ^= stream[j];
        v[j+1] ^= stream[j+1];
        i++;
    }
}



/*HACHAGE et CODE AUTHENTIFICATION*/

void hash(uint32_t *v, uint32_t vect[2], uint32_t h[2], int nb_blocks){
    int i = 0;

    while (i< nb_blocks)
    {
        int j = 4*i;

        uint32_t tmp[2];
        tmp[0] = vect[0];
        tmp[1] = vect[1];

        uint32_t key[4];
        key[0] = v[j];
        key[1] = v[j+1];
        key[2] = v[j+2];
        key[3] = v[j+3];

        ecb_encrypt(tmp, key, 1);
        vect[0] = tmp[0]^vect[0];
        vect[1] = tmp[1]^vect[1];

        // Met a jour le resultat final
        h[0] = vect[0];
        h[1] = vect[1];
        
        i++;
    }
}

void concat_uint32(uint32_t *v, uint32_t k[4], uint32_t *tmp, int nb_blocks){
    for(int j = 0; j < 4; j++){
        tmp[j] = k[j];
    }

    int j = 0;
    for(int i = 4; i < nb_blocks+4; i++){
        tmp[i] = v[j];
        j++;
    }
}


uint32_t *hash_mac(uint32_t *v, uint32_t vect[2], uint32_t k[4], int nb_blocks){
    uint32_t *mac = malloc(2*sizeof(uint32_t));
    if(mac==NULL) return NULL;

    uint32_t i_vect[2] = {vect[0], vect[1]};

    int size = 2*nb_blocks + 4;
    uint32_t tmp[size];
    
    // Concatenation
    concat_uint32(v, k, tmp, 2*nb_blocks);

    uint32_t c[2];
    hash(tmp,vect,c,size/4);

  
    uint32_t t[8] = {0};
    concat_uint32(c,k,t,2);

    hash(t,i_vect,mac,2);
    
    return mac;
}


int hash_mac_verification(uint32_t *v, uint32_t k[4], uint32_t c[2], uint32_t vect[2], int nb_blocks){
    uint32_t *c_hash_mac = hash_mac(v, vect, k, nb_blocks);
    for(int i = 0; i < 2; i++){
        if(c[i] != c_hash_mac[i]) {
            //printf("c_hash_mac : %u %u\n", c_hash_mac[0], c_hash_mac[1]);
            //printf("c : %u %u\n", c[0], c[1]);
            free(c_hash_mac);
            return 0;
        }
    }

    printf("c_hash_mac : %u %u\n", c_hash_mac[0], c_hash_mac[1]);
    //printf("c : %u %u\n", c[0], c[1]);
    free(c_hash_mac);
    return 1;
}




uint32_t *cbc_encrypt_mac(uint32_t *v, uint32_t k[4], uint32_t vect[2], uint32_t vect_h[2], int nb_blocks){
    uint32_t tmp0[2];
    tmp0[0] = vect[0];
    tmp0[1] = vect[1];

    cbc_encrypt(v,tmp0,k,nb_blocks); // Retourne le message chiffrer
    printf("Message chiffrer : %u %u\n", v[0], v[1]);

    uint32_t *code_auth = malloc(2*sizeof(uint32_t));
    if(code_auth==NULL){
        printf("Allocation-Error\n");
    }

    uint32_t tmp1[2];
    tmp1[0] = vect_h[0];
    tmp1[1] = vect_h[1];

    code_auth = hash_mac(v,tmp1,k,nb_blocks);
    if(code_auth==NULL){
        printf("error-cbc-encrypt-mac\n");
    }

    printf("Code d'authentification : %u %u\n", code_auth[0], code_auth[1]);

    return code_auth;
}


int cbc_decrypt_mac(uint32_t *v, uint32_t *code_auth, uint32_t k[4], uint32_t vect[2], uint32_t vect_h[2], int nb_blocks){
    if(hash_mac_verification(v,k,code_auth,vect_h,nb_blocks) == 1){
        cbc_decrypt(v,vect,k,nb_blocks);
        printf("Message dechiffrer : %u %u\n", v[0], v[1]);
        return 1;
    }
    printf("Le message a ete altere en cours de route\n");
    return 0;
}


// EXPLOITATION DE FAILLE TEA

// question c
void attaque_tea(uint32_t *v,uint32_t k[4],uint32_t vect[2],int nb_block){
    int i ;
    uint32_t vect_tmp[2] = {vect[0],vect[1]};
    uint32_t v2[2*nb_block];
    for(i=0;i<2*nb_block;i++){
       v2[i]= v[i];
    }
    uint32_t t = 0b10000000000000000000000000000000;
    v2[0] = v2[0]^t;
    v2[1] = v2[1]^t;
    v2[2] = v2[2]^t;
    v2[3] = v2[3]^t;
    
    printf("Message v : %u %u\n", v[0], v[1]);
    uint32_t *code = hash_mac(v,vect_tmp,k,nb_block);
    printf("Code generer : %u %u\n", code[0], code[1]);
  
    printf("Message v2 : %u %u\n", v2[0], v2[1]);
    int x = hash_mac_verification(v2,k,code,vect,nb_block);
   
    if(x == 1)
        printf("Attaque reussi !!!! \n");
    else 
        printf("Echec d'Attaque \n");

   
}


// FONCTION TEMPORAIRE
void print_block(const char *label, uint32_t v[2]) {
    printf("%s : %u %u\n", label, v[0], v[1]);
}

void copy_msg(uint32_t *dst, uint32_t *src, int size) {
    for (int i = 0; i < size; i++) {
        dst[i] = src[i];
    }
}

void copy_vect(uint32_t dst[2], uint32_t src[2]) {
    dst[0] = src[0];
    dst[1] = src[1];
}

void copy_key(uint32_t dst[4], uint32_t src[4]) {
    for (int i = 0; i < 4; i++) {
        dst[i] = src[i];
    }
}


int main() {
    uint32_t k[4] = {
        0b01110100011110101010010010010010,
        0b11110000101010100011010101101000,
        0b00100010111010010111010110110011,
        0b00001010110111010110100110100011
    };

    uint32_t v[8] = {
        0b01010101010101010101010101010101,
        0b11111111111111110000000000000000,
        0b10101010101010101010101010101010,
        0b10101010101010101010101010101010,
        0b01010101010101010101010101010101,
        0b01010101010101010101010101010101,
        0b10101010101010101010101010101010,
        0b10101010101010101010101010101010
    };

    uint32_t iv[2] = {
        0b00101101110101110101110010110001,
        0b01110101101101100010101101010011
    };

    uint32_t iv_hash[2] = {
        iv[0],
        iv[1]
    };

    int nb_blocks = 4;

    printf("\n=== TEST 1 : Feistel bloc simple ===\n");
    {
        uint32_t bloc[2] = {v[0], v[1]};
        uint32_t original[2] = {v[0], v[1]};

        print_block("Message original", bloc);

        feistel_enc(bloc, k);
        print_block("Chiffré", bloc);

        feistel_dec(bloc, k);
        print_block("Déchiffré", bloc);
    }

    printf("\n=== TEST 2 : ECB ===\n");
    {
        uint32_t msg[8];
        copy_msg(msg, v, 8);

        ecb_encrypt(msg, k, nb_blocks);
        printf("ECB chiffré : %u %u ...\n", msg[0], msg[1]);

        ecb_decrypt(msg, k, nb_blocks);
        printf("ECB déchiffré : %u %u %u %u ...\n", msg[0], msg[1], msg[2], msg[3]);

    }

    printf("\n=== TEST 3 : CBC ===\n");
    {
        uint32_t msg[8];
        uint32_t iv_enc[2];
        uint32_t iv_dec[2];

        copy_msg(msg, v, 8);
        copy_vect(iv_enc, iv);
        copy_vect(iv_dec, iv);

        cbc_encrypt(msg, iv_enc, k, nb_blocks);
        printf("CBC chiffré : %u %u ...\n", msg[0], msg[1]);

        cbc_decrypt(msg, iv_dec, k, nb_blocks);
        printf("CBC déchiffré : %u %u ...\n", msg[0], msg[1]);

    }

    printf("\n=== TEST 4 : OFB ===\n");
    {
        uint32_t msg[8];
        uint32_t stream[8];
        uint32_t iv_ofb[2];

        copy_msg(msg, v, 8);
        copy_vect(iv_ofb, iv);

        ofb_stream(stream, iv_ofb, k, nb_blocks);
        ofb_encrypt(msg, stream, nb_blocks);
        printf("OFB chiffré : %u %u ...\n", msg[0], msg[1]);

        ofb_encrypt(msg, stream, nb_blocks);
        printf("OFB déchiffré : %u %u ...\n", msg[0], msg[1]);
    }

    printf("\n=== TEST 5 : Hash ===\n");
    {
        uint32_t msg[8];
        uint32_t h[2];  // Pour stocker le resultat du hache generer
        uint32_t ivh[2];

        copy_msg(msg, v, 8);
        copy_vect(ivh, iv_hash);

        hash(msg, ivh, h, nb_blocks);
        printf("Hash : %u %u\n", h[0], h[1]);
    }

    printf("\n=== TEST 6 : HMAC ===\n");
    {
        uint32_t msg[8];
        uint32_t ivh[2];

        copy_msg(msg, v, 8);
        copy_vect(ivh, iv_hash);

        uint32_t *mac = hash_mac(msg, ivh, k, nb_blocks);
        printf("MAC : %u %u\n", mac[0], mac[1]);

        uint32_t ivh_verif[2];
        copy_vect(ivh_verif, iv_hash);

        int ok = hash_mac_verification(msg, k, mac, ivh_verif, nb_blocks);

        if (ok)
            printf("Vérification MAC : OK\n");
        else
            printf("Vérification MAC : ERREUR\n");

        free(mac);
    }

    printf("\n=== TEST 7 : CBC + MAC ===\n");
    {
        uint32_t msg[8];
        uint32_t iv_enc[2];
        uint32_t iv_dec[2];
        uint32_t ivh[2];

        copy_msg(msg, v, 8);
        copy_vect(iv_enc, iv);
        copy_vect(iv_dec, iv);
        copy_vect(ivh, iv_hash);

        uint32_t *code = cbc_encrypt_mac(msg, k, iv_enc, ivh, nb_blocks);

        uint32_t ivh_verif[2];
        copy_vect(ivh_verif, iv_hash);

        int ok = cbc_decrypt_mac(msg, code, k, iv_dec, ivh_verif, nb_blocks);

        if (ok)
            printf("Déchiffrement authentifié : OK\n");
        else
            printf("Déchiffrement authentifié : ERREUR\n");

        free(code);
    }

    printf("\n=== TEST 8 : Attaque TEA ===\n");
    {
        uint32_t msg[8];
        uint32_t iv_attack[2];

        copy_msg(msg, v, 8);
        copy_vect(iv_attack, iv_hash);

        attaque_tea(msg, k, iv_attack, nb_blocks);
    }

    return 0;
}