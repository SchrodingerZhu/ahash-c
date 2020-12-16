//
// Created by schrodinger on 12/16/20.
//
#include <definitions.h>
#include <assert.h>
#include <stdio.h>

void shuffle_no_collide_with_aes() {
#ifndef USE_FALLBACK
    uint8_t value[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    aes128_t zero_mask_encode = aes_encode((aes128_t){}, (aes128_t){});
    aes128_t zero_mask_decode = aes_decode((aes128_t){}, (aes128_t){});
    for (int i = 0; i < 16; ++i) {
        value[i] = 1;
        aes128_t encode = aes_encode(*(aes128_t * )(value), zero_mask_encode);
        aes128_t decode = aes_decode(*(aes128_t * )(value), zero_mask_decode);
        aes128_t shuffled = shuffle(*(aes128_t * )(value));
        uint8_t *encode_vec = (uint8_t * ) & encode;
        uint8_t *decode_vec = (uint8_t * ) & decode;
        uint8_t *shuffled_vec = (uint8_t * ) & shuffled;
        for (int j = 0; j < 16; ++j) {
            printf("val[%d]=%d, ", j, value[j]);
            printf("vec[%d]=%d, ", j, shuffled_vec[j]);
            printf("enc[%d]=%d, ", j, encode_vec[j]);
            printf("dec[%d]=%d\n", j, decode_vec[j]);
            if (shuffled_vec[j] != 0) {
                assert(encode_vec[j] == 0);
                assert(decode_vec[j] == 0);
            }
        }
        printf("\n");
        value[i] = 0;
    }
#endif
}


int main() {
    shuffle_no_collide_with_aes();
}