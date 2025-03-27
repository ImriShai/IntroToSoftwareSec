#include <stdio.h>
#include <fcntl.h>






int main(){
    int fd = open("log.txt", O_WRONLY | O_APPEND);
    write(fd, "test", 4);
    close(fd);
    return 0;
}