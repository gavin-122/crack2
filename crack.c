#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 6767;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!

char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext

    if (plaintext == NULL) 
    {
        return NULL;
    }
    int plen = (int) strlen(plaintext);
    char *hash_str = md5(plaintext, plen);
    if (hash_str == NULL) 
    {
        return NULL;
    }

    // Open the hash file

     FILE *hf = fopen(hashFilename, "r");
    if (!hf) 
    {
        fprintf(stderr, "Error: could not open hash file '%s'\n", hashFilename);
        free(hash_str);
        return NULL;
    }

    // Loop through the hash file, one line at a time.

     char line[HASH_LEN + 8];
    while (fgets(line, sizeof(line), hf))

    // Attempt to match the hash from the file to the
    // hash of the plaintext.

    {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' ||line[len-1] == ' ' || line[len-1] == '\t')) 
        {
            line[--len] = '\0';
        }

        if (len != 32) 
        {
            continue;
        }

        if (strcmp(hash_str, line) == 0) 
        {
            // If there is a match, you'll return the hash.
            fclose(hf);
            return hash_str;
        }
    }

    // If there is a match, you'll return the hash.
    // If not, return NULL.

    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?

    fclose(hf);
    free(hash_str);

    // Modify this line so it returns the hash
    // that was found, or NULL if not found.

    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these two lines and complete the rest
    // of the main function below.

    char *found = tryWord("hello", "hashes00.txt");
    printf("%s %s\n", found, "hello");


    // Open the dictionary file for reading.

    char *hash_file = argv[1];
    char *dict_file = argv[2];
    FILE *df = fopen(dict_file, "r");
    if (!df) 
    {
        fprintf(stderr, "Error: could not open dictionary file '%s'\n", dict_file);
        if (found) free(found);
        exit(1);
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.

     char word[PASS_LEN + 8];
    int cracked = 0;
    while (fgets(word, sizeof(word), df))
    {
    size_t wlen = strlen(word);
        while (wlen > 0 && (word[wlen-1] == '\n' || word[wlen-1] == '\r' || word[wlen-1] == ' ' || word[wlen-1] == '\t')) 
        {
            word[--wlen] = '\0';
        }
        if (wlen == 0) 
        continue;

    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello

    char *res = tryWord(word, hash_file);
        if (res != NULL) 
        {
            printf("%s %s\n", res, word);
            free(res);
            cracked++;
        }
    }
    
    // Close the dictionary file.
    fclose(df);

    // Display the number of hashes that were cracked.
        printf("%d hashes cracked!\n", cracked);

    // Free up any malloc'd memory?
    if (found) free(found);
    return 0;
}

