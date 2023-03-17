#include <Arduino.h>
#include "ecdh.h"

#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/entropy_poll.h"



// STRUCTS AND FUNCS


//mbedtls_entropy_context - this structure holds the entropy context, including the entropy sources, accumulator, and other paramters
mbedtls_entropy_context entropy; 



//mbedtls_ctr_drbg_context - this structure holds the CTR-DRBG context, including the internal state, key, and other parameters.
mbedtls_ctr_drbg_context ctr_drbg;
//ctr_drgb = counter mode - Deterministic Random Bit Generator

void mbedtls_random_init() {
  mbedtls_entropy_init(&entropy); //initializes the entropy context
  mbedtls_ctr_drbg_init(&ctr_drbg); //Initializes the CTR-DRBG context

  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);  //This seeds the CTR-DRBG generator with entropy collected from an entropy source
  if (ret != 0) {
    Serial.printf("Failed to seed the random number generator. Error code: %d\n", ret);
  }
}

//mbedtls_entropy_func - this is a callback function that collects entropy from the sources and provides it to the CTR-DRBG generator

int mbedtls_random(uint8_t *output, size_t len) {
  return mbedtls_ctr_drbg_random(&ctr_drbg, output, len); //this generates random random numbers using the CTR-DRGB algorithm
}
//---------------------------------------------------------------------------------------------
//CODE USING THE PREVIOUS RNG
//
//typedef struct
//{
//  uint32_t a;
//  uint32_t b;
//  uint32_t c;
//  uint32_t d;
//} prng_t;
//
//static prng_t prng_ctx;
//
//static uint32_t prng_rotate(uint32_t x, uint32_t k)
//{
//  return (x << k) | (x >> (32 - k));
//}
//
//static uint32_t prng_next(void)
//{
//  uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27);
//  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17);
//  prng_ctx.b = prng_ctx.c + prng_ctx.d;
//  prng_ctx.c = prng_ctx.d + e;
//  prng_ctx.d = e + prng_ctx.a;
//  return prng_ctx.d;
//}
//
//static void prng_init(uint32_t seed)
//{
//  uint32_t i;
//  prng_ctx.a = 0xf1ea5eed;
//  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;
//
//  for (i = 0; i < 31; ++i)
//  {
//    (void)prng_next();
//  }
//}

//---------------------------------------------------------------------------------------------


//This function is used to put the keys in raw hex

void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    Serial.printf("%02x", data[i]);
  }
  Serial.println();
}




static void ecdh_demo(void)
{
  static uint8_t puba[ECC_PUB_KEY_SIZE];
  static uint8_t prva[ECC_PRV_KEY_SIZE];
  static uint8_t seca[ECC_PUB_KEY_SIZE];
  static uint8_t pubb[ECC_PUB_KEY_SIZE];
  static uint8_t prvb[ECC_PRV_KEY_SIZE];
  static uint8_t secb[ECC_PUB_KEY_SIZE];
  uint32_t i;

  /* 0. Initialize and seed random number generator */
//  static int initialized = 0;
//  if (!initialized)
//  {
//    prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
//    initialized = 1;
//  }

  /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
  int ret = mbedtls_ctr_drbg_random(&ctr_drbg, prva, ECC_PRV_KEY_SIZE);
  if (ret != 0) {
    Serial.printf("mbedtls_ctr_drbg_random failed: %d\n", ret);
  }
    //This is the key before it is adjusted based on the constraints for Alice
    Serial.print("This is ALICE'S PRIVATE KEY BEFORE ADJUSTMENT: ");
    print_hex(prva, ECC_PRV_KEY_SIZE);


  unsigned long start_time_a = millis();
  assert(ecdh_generate_keys(puba, prva));
  unsigned long end_time_a = millis();
  unsigned long duration_a = end_time_a - start_time_a;
  
 
  /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, prvb, ECC_PRV_KEY_SIZE);
  if (ret != 0) {
    Serial.printf("mbedtls_ctr_drbg_random failed: %d\n", ret);
  }

  //This is the key before it is adjusted before the constraints for BOB

  Serial.print("This is BOB'S PRIVATE KEY BEFORE ADJUSTMENT: ");
  print_hex(prvb, ECC_PRV_KEY_SIZE);
  Serial.println();

  unsigned long start_time_b = millis();
  assert(ecdh_generate_keys(pubb, prvb));
  unsigned long end_time_b = millis();
  unsigned long duration_b = end_time_b - start_time_b;
  
  /* 3. Alice calculates S = a * Q = a * (b * g). */
  assert(ecdh_shared_secret(prva, pubb, seca));

  /* 4. Bob calculates T = b * P = b * (a * g). */
  assert(ecdh_shared_secret(prvb, puba, secb));

  /* 5. Assert equality, i.e. check that both parties calculated the same value. */
  for (i = 0; i < ECC_PUB_KEY_SIZE; ++i)
  {
    assert(seca[i] == secb[i]);
  }


    // After generating Alice's keys (Step 1)
  Serial.print("Alice's Public Key: ");
  print_hex(puba, ECC_PUB_KEY_SIZE);
  Serial.print("Alice's Private Key: ");
  print_hex(prva, ECC_PRV_KEY_SIZE);
  Serial.println();


  
  // After generating Bob's keys (Step 2)
  Serial.print("Bob's Public Key: ");
  print_hex(pubb, ECC_PUB_KEY_SIZE);
  Serial.print("Bob's Private Key: ");
  print_hex(prvb, ECC_PRV_KEY_SIZE);
  Serial.println();

  
  // After Alice calculates the shared secret (Step 3)
  Serial.print("Alice's Shared Secret: ");
  print_hex(seca, ECC_PUB_KEY_SIZE);
  // After Bob calculates the shared secret (Step 4)
  Serial.print("Bob's Shared Secret: ");
  print_hex(secb, ECC_PUB_KEY_SIZE);
  Serial.println();

  
  //Time taken to for the key generation
  Serial.printf("Time taken for Alice's key generation: %lu ms\n", duration_a);
  Serial.printf("Time taken for Bob's key generation: %lu ms\n", duration_b);
  Serial.println();
  

}


/* WARNING: This is not working correctly. ECDSA is not working... */
void ecdsa_broken()
{
  static uint8_t  prv[ECC_PRV_KEY_SIZE];
  static uint8_t  pub[ECC_PUB_KEY_SIZE];
  static uint8_t  msg[ECC_PRV_KEY_SIZE];
  static uint8_t  signature[ECC_PUB_KEY_SIZE];
  static uint8_t  k[ECC_PRV_KEY_SIZE];
  uint32_t i;

  
//  srand(millis());
  srand(42);

  for (i = 0; i < ECC_PRV_KEY_SIZE; ++i) {
    prv[i] = rand();
    msg[i] = prv[i] ^ rand();
    k[i] = rand();
  }

/* int ecdsa_sign(const uint8_t* private, const uint8_t* hash, uint8_t* random_k, uint8_t* signature);
   int ecdsa_verify(const uint8_t* public, const uint8_t* hash, uint8_t* signature);                          */

  ecdh_generate_keys(pub, prv);
  /* No asserts - ECDSA functionality is broken... */
  ecdsa_sign((const uint8_t*)prv, msg, k, signature);
  ecdsa_verify((const uint8_t*)pub, msg, (const uint8_t*)signature); /* fails... */
}




//Global Variables
int ncycles = 1;



void setup() {
    // Initialize serial communication for debugging
  Serial.begin(115200);

  // Initialize mbedtls_random
  mbedtls_random_init();

  // Set the number of cycles (optional)
  ncycles = 1; // Set the desired number of cycles

  unsigned long start_time_total = millis(); // Start time for the total program execution

  while (ncycles > 0) {
    loop();
    ncycles--;
  }

  // Calculate the total time taken for the program to run
  unsigned long end_time_total = millis();
  unsigned long duration_total = end_time_total - start_time_total;

  // Print the total time taken for the program to run
  Serial.println();
  Serial.printf("Total time taken for the program to run: %lu ms\n", duration_total);
}


void loop() {
  static int current_cycle = 0; // Move the variable inside the loop function

  if (current_cycle < ncycles) {
    Serial.printf("Cycle %d:\n", current_cycle + 1);
    ecdh_demo();
    ecdsa_broken();
    current_cycle++;
  } else {
    // Stop executing the loop when all cycles are completed
    delay(1000);
  }
}
