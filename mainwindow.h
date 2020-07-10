#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
//#include "winsock2.h"
//#pragma comment(lib,"Ws2_32")

#include "netinet/in.h"
#include "unistd.h"
#include "sys/socket.h"
#include <sys/types.h>
#include <arpa/inet.h>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    typedef struct ip_header
    {
            unsigned int headlen:4;            //IP头长度4
            unsigned int version:4;            //IP版本号4
            unsigned char tos;                 //服务类型8
            unsigned short id;                 //ID号16
            unsigned short flag;               //标记 3位标志+13位片偏移
            unsigned char ttl;                 //生存时间8
            unsigned char prot;                //协议8
            unsigned short checksum;           //效验和16
            unsigned int sourceIP;             //源IP32
            unsigned int destIP;               //目的IP32
    } IPHeader;

    //解码结果
    typedef struct
    {
        unsigned short usSeqNo;		  //包序列号 输入
        unsigned long dwRoundTripTime; //往返时间 输入输出
        in_addr dwIPaddr;	  //对端IP地址 输出
    } DecodeResult;//ip头部定义，具体含义，参考ip头部格式

    typedef struct icmp_header
    {
        unsigned char   icmp_type;   // 消息类型8
        unsigned char   icmp_code;   // 代码8
        unsigned short icmp_checksum; // 校验和16

        unsigned short icmp_id;   // 用来惟一标识此请求的ID号，通常设置为进程ID16
        unsigned short icmp_sequence; // 序列号 数据随意，大小也是随意16
        unsigned long   icmp_timestamp; // 时间戳
    } IcmpHeader;

    unsigned short CheckSum(unsigned short *pBuf,int nLen);
    int SendEchoRequest(int s, LPSOCKADDR_IN lpstToAddr,DecodeResult *stDecodeResult);
    bool DecodeIcmpResponse(char* pBuf, int iPacketSize, DecodeResult& stDecodeResult,char* timeinfo);
    int RecvEchoReply(int s, SOCKADDR_IN *saFrom, SOCKADDR_IN *saDest, DecodeResult *stDecodeResult,char* destip);

    int Ping(char* stdSzDestIP);


private:
    Ui::MainWindow *ui;

public slots:
    void startScan();
};
#endif // MAINWINDOW_H
