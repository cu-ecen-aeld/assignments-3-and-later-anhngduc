
#include <stdio.h>
#include <syslog.h>



int main ( int argc, char **argv ) {

    openlog(NULL,0,LOG_USER);
    
    if (argc != 3){
        syslog(LOG_ERR, "Invalid number of args. <command> <path> <string>");
        return 1;
    }

    char *m_path = argv[1];
    char *m_string = argv[2];

    FILE *fptr;
    syslog(LOG_DEBUG, "Writing %s to %s", m_string, m_path);

    // Open and write string to file
    fptr = fopen(m_path, "w");    
    fprintf(fptr, "%s",m_string);

    // Close the file
    fclose(fptr);

    return 0;

}