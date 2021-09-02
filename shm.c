#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>


int shm_w(key_t key)
{
   int shm_id;
   // assign a ID to shared memory segment (key_t key)
   char *shm_ptr; // pointer to shared memory segment

   char *msg = "run"; // message to write in shm segment
   size_t msg_siz = strlen(msg); // size of message (without NULL terminator)

   // Setup shared memory, get shm size equal to msg+NULL terminator
   if ((shm_id = shmget(key, (msg_siz+1)*sizeof(char), IPC_CREAT | 0666)) < 0)
   {
      printf("Error getting shared memory shm_id");
      return(-10);
   }
   // Attach shared memory
   if ((shm_ptr = shmat(shm_id, NULL, 0)) == (char *) -1)
   {
      printf("Error attaching shared memory id");
      return(-20);
   }
   // copy "run" to shared memory, take care of NULL terminator
   memcpy(shm_ptr, msg, (msg_siz+1)*sizeof(char));
   shmdt(shm_ptr);   
   return shm_id;
}

void shm_free(int shm_id)
{
   shmctl(shm_id, IPC_RMID, NULL);
}
