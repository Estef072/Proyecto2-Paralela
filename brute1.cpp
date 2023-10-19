#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <limits.h>

using namespace std;

#define DEFAULT_KEY 8014398509481983LL;

char search[] = "es una prueba de";

/**
 * Converts a long number to bytes
 * @param input the long number that will be converted
 * @param output the long number transformed to bytes
*/
void long_to_bytes(long long input, unsigned char *output)
{
  for (int i = 7; i >= 0; i--)
  {
    output[i] = input & 0xFF;
    input >>= 8;
  }
}

/**
 * Decrypts a text
 * @param mykey key that will be used to desencrypt
 * @param ciph chypered text that will be decrypted (out)
 * @param len the size of the chyper
*/
void decrypt(long long mykey, unsigned char* ciph, int len)
{
	unsigned char key_bytes[8];
	long_to_bytes(mykey, key_bytes);
	DES_cblock key;
	memcpy(key, key_bytes, 8);
	DES_key_schedule key_schedule;
	DES_set_key(&key, &key_schedule);

  for (size_t i = 0; i < len; i += 8)
  {
    DES_ecb_encrypt((const_DES_cblock*)(ciph + i), (const_DES_cblock*)(ciph + i), &key_schedule, DES_DECRYPT);
  }
}

/**
 * Encrypts a text
 * @param mykey the key that will be used to encrypt
 * @param ciph plain text that will be encrypted
 * @param ciph_len pthe lenght of the text
*/
void encrypt(long long mykey, unsigned char *ciph, size_t ciph_len)
{
  unsigned char key_bytes[8];
  long_to_bytes(mykey, key_bytes);
  DES_cblock key;
  memcpy(key, key_bytes, 8);
  DES_key_schedule key_schedule;
  DES_set_key(&key, &key_schedule);

  for (size_t i = 0; i < ciph_len; i += 8)
  {
    DES_ecb_encrypt((const_DES_cblock*)(ciph + i), (const_DES_cblock*)(ciph + i), &key_schedule, DES_ENCRYPT);
  }
}

/**
 * Checks if the key is the correct one
 * @param key_guess key that will be tested
 * @param ciph cyphered text
 * @param len cypher text size
*/
int tryKey(long long key_guess, unsigned char* ciph, int len)
{
  unsigned char *decrypted = (unsigned char *)calloc(len, sizeof(unsigned char));
  memcpy(decrypted, ciph, len);
  decrypt(key_guess, decrypted, len);

  // Check if the decrypted message contains the plaintext
  if (strstr((char *)decrypted, search) != NULL)
  {
    memcpy(ciph, decrypted, len);
    free(decrypted);
    return 1;
  }

  free(decrypted);
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

/**
 * Gets the content of a file
 * @param path location of the file to read
 * @returns the content of the file
*/
string getFileBody (string path)
{
  int exists = 0;
  string data, aux;
  ifstream file(path);

  // There was a problem reading the file
  if (file.fail())
  {
    cout << "[File] Error reading file " << path << endl;
    MPI_Finalize();
    exit(-1);
  }

  // Reads all the lines
  while (getline(file, aux))
  {
    data += aux;
    exists = 1;
    if (file.peek() != EOF)
    {
      data += "\n";
    }
  }
  file.close();

  // The file was empty
  if (exists == 0)
  {
    cout << "[File] Empety file encountered" << endl;
    MPI_Finalize();
    exit(-1);
  }

  return data;
}


int main(int argc, char *argv[])
{
  int N, id;
  long long upper = (1LL << 56); //upper bound DES keys 2^56
  long long mylower, myupper, key;

  double tstart, tend;

  unsigned char* cypher;
  string fileBody;
  size_t cypher_len, file_len;

  MPI_Request request;
  MPI_Status status;
  MPI_Comm comm = MPI_COMM_WORLD;

  long long found = -1L;
  int ready = 0;

  //INIT MPI
  MPI_Init(&argc, &argv);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  // Sends the content of the file to the other proccesses
  if (id == 0)
  {
    fileBody = getFileBody("./data.txt");
    file_len = fileBody.size();

    for(int node = 1; node < N; node++)
    {
      MPI_Send(&file_len, 1, MPI_LONG_LONG, node, 0, comm);
    }
  }
  else
  {
    MPI_Recv(&file_len, 1, MPI_LONG_LONG, 0, 0, comm, MPI_STATUS_IGNORE);
  }

  unsigned char* message[file_len];

  if (id == 0)
  {
    strcpy((char*) message, fileBody.data());
    for(int node = 1; node < N; node++)
    {
      MPI_Send(message, sizeof(unsigned char) * file_len, MPI_UNSIGNED_CHAR, node, 0, comm);
    }
  }
  else
  {
    MPI_Recv(message, sizeof(unsigned char) * file_len, MPI_UNSIGNED_CHAR, 0, 0, comm, MPI_STATUS_IGNORE);
  }

  // Gets the key from the params
  if (argc > 1)
  {
    string temp_key = argv[1];

    if (check_number(temp_key))
    {
      key = atoll(temp_key.c_str());
      if (id == 0) {
        cout << "[0] Using custom key " << key << endl;
      }
    }
    else
    {
      key = DEFAULT_KEY;
      if (id == 0) {
        cout << "[0] Error on input key, using default instead " << key << endl;
      }
    }
  } else {
    key = DEFAULT_KEY;
    if (id == 0) {
      cout << "[0] Using default key" << key << endl;
    }
  }

  // Starts encryption
  cypher_len = file_len + (8 - file_len % 8);
  cypher = (unsigned char*)calloc(cypher_len, sizeof(unsigned char));
  memcpy(cypher, message, file_len);
  encrypt(key, cypher, cypher_len);

  // Distributes the work
  long long range_per_node = upper / N;
  mylower = range_per_node * id;
  myupper = range_per_node * (id + 1) - 1;

  if (id == N - 1) myupper = upper;
  printf("Process [%d] lower = %llu upper = %llu\n", id, mylower, myupper);

  // Doesn't block and checks if the someone found the key
  MPI_Irecv(&found, 1, MPI_LONG_LONG, MPI_ANY_SOURCE, 1, comm, &request);

  tstart = MPI_Wtime();
  if (found == -1) {
    // Approach 1
    for (long long i = mylower; i < myupper; ++i)
    {
      MPI_Test(&request, &ready, MPI_STATUS_IGNORE);
      if (ready) break;  // Key found by another proccess

      if (tryKey(i, cypher, cypher_len))
      {
        found = i;
        cout << "[" << id << "] Key found" << endl;
        for(int node = 0; node < N; node++) {
            MPI_Send(&found, 1, MPI_LONG_LONG, node, 1, comm);
        }
        break;
      }
    }
  }
  tend = MPI_Wtime();

  if (id == 0) // Waints for the rest
  {
    MPI_Wait(&request, &status);

    cout << endl << "[0] Took " << (tend - tstart) << " s to run" << endl;

    memcpy(cypher, message, file_len);
    encrypt(key, cypher, cypher_len);
    printf("[0] Encrypted text: %s\n", cypher);

    

    decrypt(found, cypher, cypher_len);
    printf("[0] Dencrypted text: %s\n", cypher);
  }

  // // FInishing MPI
  cout << "[" << id << "] Process exiting" << endl;

  MPI_Finalize();
  exit(0);
}