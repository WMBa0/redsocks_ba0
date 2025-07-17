#include <netinet/in.h>
#include <arpa/inet.h>
int main(){
    struct sockaddr_in server_addr;
    
    //初始化结构体
    memset(&server_addr,0,sizeof(server_addr));
    server_addr.sin_family= AF_INET;//初始化协议族
    server_addr.sin_port=htons(8080);//设置端口号
    inet_pton(AF_INET,"192.168.1.1",&server_addr.sin_addr);
    


}