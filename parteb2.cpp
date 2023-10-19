#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <fstream>
#include <unistd.h>
#include <openssl/des.h>
#include <openssl/rand.h>

using namespace std;

#define KEY_SPACE_SIZE 4294967296 // 2^32 possible keys

void long_to_bytes(long long input, unsigned char *output)
{
	for (int i = 7; i >= 0; i--)
	{
		output[i] = input & 0xFF;
		input >>= 8;
	}
}

// descifra un texto dado una llave
void decrypt(long long mykey, char *ciph, int len, unsigned char *iv)
{
	unsigned char key_bytes[8];
	long_to_bytes(mykey, key_bytes);
	DES_cblock key;
	memcpy(key, key_bytes, 8);
	DES_key_schedule key_schedule;
	DES_set_key_unchecked(&key, &key_schedule);

	DES_cblock ivec;
	memcpy(ivec, iv, sizeof(DES_cblock));

	DES_ncbc_encrypt((const unsigned char*)ciph, (unsigned char*)ciph, len, &key_schedule, &ivec, DES_DECRYPT);
}

// cifra un texto dado una llave
void encrypt(long long mykey, char *ciph, int len, unsigned char *iv)
{
	unsigned char key_bytes[8];
	long_to_bytes(mykey, key_bytes);
	DES_cblock key;
	memcpy(key, key_bytes, 8);
	DES_key_schedule key_schedule;
	DES_set_key_unchecked(&key, &key_schedule);

	DES_cblock ivec;
	memcpy(ivec, iv, sizeof(DES_cblock));

	DES_ncbc_encrypt((const unsigned char*)ciph, (unsigned char*)ciph, len, &key_schedule, &ivec, DES_ENCRYPT);
}

// palabra clave a buscar en texto descifrado para determinar si se rompio el codigo
char search[] = "es una prueba de";

int tryKey(long long initial_guess, char *ciph, int len, unsigned char *iv)
{
	for (long long key_guess = initial_guess; key_guess < KEY_SPACE_SIZE; ++key_guess)
	{
		unsigned char *decrypted = (unsigned char *)calloc(len, sizeof(unsigned char));
		memcpy(decrypted, ciph, len);

		decrypt(key_guess, (char*)decrypted, len, iv);

		// Check if the decrypted message contains the plaintext
		if (strstr((char *)decrypted, search) != NULL)
		{
			memcpy(ciph, decrypted, len);
			return 1;
		}

		free(decrypted);
	}
	return 0;
}

/**
 * Checks if a string is a valid integer
 * @param str the string that will be tested
 * @returns 1 if valid else 0
*/
int check_number(string str) {
  for (int i = 0; i < str.length(); i++)
  {
    if (isdigit(str[i]) == 0)
    {
      return 0;
    }
  }

  return 1;
}

string getFileBody (string path)
{
	int exists = 0;
	string data, aux;
	ifstream file(path);
	data = "";

	// Problem reading file
	if (file.fail())
	{
		printf("[File] Error reading file %s", path.c_str());
		exit(-1);
	}

	// Reading line by line
	while (getline(file, aux))
	{
		data += aux;
		exists = 1;
		if (file.peek() != EOF)
		{
			data += '\n';
		}
	}
	file.close();

	// File is empty
	if (!exists)
	{
		printf("[File] Empty file");
		exit(-1);
	}

	return data;
	
}

long long the_key = 8014398509481984L;

int main(int argc, char *argv[])
{
	long long found = 0L;
	unsigned char iv[8];
	string fileBody;
	fileBody = getFileBody("./data.txt");

	// Generate a 8-byte IV
	if (RAND_bytes(iv, 8) != 1)
	{
		printf("Error generating random bytes.\n");
		return 1;
	}

	if (argc > 1) {
		string tempKey = argv[1];
		if (check_number(tempKey))
		{
			the_key = atoll(tempKey.c_str());
		}
		else
		{
			printf("[Input] Error on input key, using default instead\n");
		}
	}
	else{
		printf("[Input] No input provided, using default key instead\n");
	}

	// Pad the message with null bytes if it is not a multiple of 8 bytes
	size_t message_len = fileBody.size();
	size_t padded_len = message_len + (8 - message_len % 8);
	unsigned char *padded_message = (unsigned char *)calloc(padded_len, sizeof(unsigned char));
	memcpy(padded_message, fileBody.c_str(), message_len);

	// Encrypt the padded message
	encrypt(the_key, (char*)padded_message, padded_len, iv);

	// Print the encrypted ciphertext
	printf("Encrypted ciphertext: ");
	for (size_t i = 0; i < padded_len; ++i)
	{
		printf("%02x", padded_message[i]);
	}

	// Decrypt the padded message
	double time_spent = 0.0;
	clock_t initial, end;
	initial = clock();
	if (tryKey(found, (char*)padded_message, padded_len, iv))
	{
		printf("\nOutput luego del trykey: %s\n", padded_message);
	}
	end = clock();
	time_spent += (double)(end - initial) / CLOCKS_PER_SEC;
	printf("\nTime to find Key: %f", time_spent);
}