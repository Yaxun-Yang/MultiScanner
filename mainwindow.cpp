#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->startScanButton,&QPushButton::clicked,this,&MainWindow::startScan);
}

MainWindow::~MainWindow()
{
    delete ui;
}

unsigned short MainWindow::CheckSum(unsigned short *buff, int size)
{
    unsigned long cksum = 0;
    while(size>1)
    {
        cksum += *buff++;
        size -= sizeof(unsigned short);
    }
    // 是奇数
    if(size)
    {
        cksum += *(unsigned char*)buff;
    }
    // 将32位的chsum高16位和低16位相加，然后取反
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);    // ???
    return (unsigned short)(~cksum);
}

int MainWindow::SendEchoRequest(int socketRaw, (const sockaddr *) addrDest,DecodeResult *stDecodeResult)
{
    int nRet;
    //创建发送的ICMP数据包
    char icmpSendBuff[sizeof(IcmpHeader)];

    //填充数据包
    memset(icmpSendBuff, 0, sizeof(icmpSendBuff));

    IcmpHeader * pIcmp=(IcmpHeader *)icmpSendBuff;
    //初始化ICMP包
    pIcmp->icmp_type=8;
    pIcmp->icmp_code=0;
    pIcmp->icmp_id=(unsigned short)::GetCurrentProcessId(); //线程号命名
    pIcmp->icmp_code = 0;
//    pIcmp->icmp_checksum=0;
    pIcmp->icmp_sequence=0;
    pIcmp->icmp_timestamp=0x01020304; //随意设置
    pIcmp->icmp_checksum=CheckSum((unsigned short*)pIcmp, sizeof(IcmpHeader));

    stDecodeResult->dwRoundTripTime = gettimeofday();
    //开始发送和接受ICMP封包
    nRet=sendto(socketRaw,icmpSendBuff,sizeof(icmpSendBuff),MSG_NOSIGNAL,&addrDest,sizeof(sockaddr_in));

    //SOCKET_ERROR win下
    if (nRet==-1)
    {
//        cout << "sendto() failed "<< nRet << endl;
        return -1;
    }
    return 0;
}

bool MainWindow::DecodeIcmpResponse(char *pBuf, int iPacketSize, MainWindow::DecodeResult &stDecodeResult,char* timeinfo)
{
    IPHeader* pIpHdr = (IPHeader*)pBuf;
    int iIpHdrLen = ((IPHeader*)pBuf)->headlen * 4;
    //    int iIpHdrLen = 20;//IPV4 ip头部，固定20字节

    //ip首部占用20字节，定位到icmp报文
    IcmpHeader* pIcmpHdr = (IcmpHeader*)(pBuf + iIpHdrLen);

    unsigned short usID;
    unsigned short usSquNo;
//    ICMP回显应答报文
    if(pIcmpHdr->icmp_type == 0) {
//        报文ID
        usID = pIcmpHdr->icmp_id;
//        序列号
        usSquNo = pIcmpHdr->icmp_sequence;
    }
//    ICMP超时差错报文
    else if (pIcmpHdr->icmp_type ==11 )
    {
        //        载荷中的IP头
       char *pInnerIpHdr = pBuf + iIpHdrLen + sizeof(IcmpHeader);
       //        载荷中的IP头长
       int iInnerIpHdrLen = ((IPHeader*)pInnerIpHdr)->headlen * 4;
//        载荷中的ICMP头
       IcmpHeader *pInnerIcmpHdr = (IcmpHeader*)(pInnerIpHdr + iInnerIpHdrLen);
//        报文ID
       usID = pInnerIcmpHdr->icmp_id;
//        序列号
       usSquNo = pInnerIcmpHdr->icmp_sequence;
    }
    else {
        return false;
    }

//    if(usID != (USHORT)GetCurrentProcessId() || usSquNo != stDecodeResult.usSeqNo) {
//        cout << "usID != (USHORT)GetCurrentProcessId() || usSquNo != stDecodeResult.usSeqNo" << endl;
//        return false;
//    }

    //返回解码结果
    stDecodeResult.dwIPaddr.s_addr =((IPHeader*)pBuf)->sourceIP; //linux下 sockaddr_in.sin_addr.s_addr=inet_addr("192.168.0.1");
    stDecodeResult.dwRoundTripTime = gettimeofday() - stDecodeResult.dwRoundTripTime;

    //    打印往返时间信息
//    if(stDecodeResult.dwRoundTripTime) {
//        cout << "   " << stDecodeResult.dwRoundTripTime << "ms" << endl;
//    }
//    else {
//        cout << "   " << "<1" << "ms" << endl;
//    }

    return true;
}

int MainWindow::RecvEchoReply(int s, sockaddr_in *saFrom, sockaddr_in *saDest, MainWindow::DecodeResult *stDecodeResult,char* destIP)
{
    int nRet;
        int nAddrLen = sizeof(struct sockaddr_in);

        //创建ICMP包接收缓冲区
        char IcmpRecvBuf[1024];
        memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));

        // 接收
        nRet = recvfrom(s,					// socket
            IcmpRecvBuf,	// buffer
            1024,	// size of buffer
            0,					// flags
            (const sockaddr *)&saFrom,	// From address
            &nAddrLen);			// pointer to address len


        //打印输出
        if (nRet != -1) //接收没有错误
        {
            char* timeinfo;
            //解码得到的数据包
            if (DecodeIcmpResponse(IcmpRecvBuf, nRet, *stDecodeResult,timeinfo))
            {
//                if (stDecodeResult->dwIPaddr.s_addr == saDest->sin_addr.s_addr)
//                {
//                    ui->outputBrowser->append(destIP);
//                    cout << "alive \n";
//                    return 1;
//                }
//                cout << "dwIPaddr.s_addr" <<  stDecodeResult->dwIPaddr.s_addr << endl;
//                cout << "saDest->sin_addr.s_addr" << saDest->sin_addr.s_addr << endl;

//                if(stDecodeResult->dwRoundTripTime) {
//                    char* time_info ="   ";
//                    strcat(time_info,(int)(stDecodeResult->dwRoundTripTime)+"ms   ");

//                    cout << "   " << stDecodeResult->dwRoundTripTime << "ms" << endl;
//                }
//                else {
//                    char* time_info="   <1ms   ";
//                    cout << "   " << "<1" << "ms" << endl;
//                }

                strcat(destIP,"  主机存活");
                ui->outputBrowser->append(destIP);
//                cout << "alive \n";
                return 1;
            }
            else {
                strcat(destIP,"  主机没有存活");
                ui->outputBrowser->append(destIP);
                return -1;
            }
        }
        else
        {
            strcat(destIP,"  请求超时");
            ui->outputBrowser->append(destIP);
            return -1;
        }
        return 0;
}

int MainWindow::Ping(char *stdSzDestIP)
{
    //linux下声明socket
    int socketRaw;

    if( (socketRaw = socket(AF_INET, SOCK_STREAM, 0)) == -1 ){
       printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);
       exit(0);
    }

    //win下下需要用WSAStartup启动Ws2_32.lib，并且要用#pragma comment(lib,"Ws2_32")来告知编译器链接该lib。linux下不需要
    //    SOCKET socketRaw;
    //    //目的地址
//    WSADATA wsaData;
//    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
//    if (iResult != 0)
//    {
//        cout << "Winsock Initialization failed" <<endl;
//        return -1;
//    }

    //创建原始套接字
    //AF_INET表示地址族为IPV4
    //SOCK_RAW表示创建的为原始套接字，若在UNIX/LINUX环境下，应该获得root权限，在Windows环境下使用管理员权限运行程序
//    socketRaw=::socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);

    int iResult;

    sockaddr_in addrDest, addrSrc;
    DecodeResult stDecodeResult;
    unsigned short usSeqNo =0;

    //超时选项
    int nTimeout=5000;

    iResult = setsockopt(socketRaw, SOL_SOCKET,SO_RCVTIMEO,(char*)&nTimeout, sizeof(nTimeout));

    memset(&stDecodeResult, 0, sizeof(DecodeResult));

    addrDest.sin_family = AF_INET;
//    addrDest.sin_port = htons(0);
    //获取扫描的ip
    //win下
    addrDest.sin_addr.s_addr=inet_addr(stdSzDestIP); //无法处理255.255.255.255
    //linux下
//    addrDest.sin_addr.s_addr=inet_addr(stdSzDestIP);

    /**发送ICMP Echo请求
     *
      */
    iResult = SendEchoRequest(socketRaw, &addrDest, &stDecodeResult);

//    cout << "SendEchoRequest result" << iResult <<  endl;

//    if (iResult == SOCKET_ERROR)
//    {
//        if (WSAGetLastError() == WSAEHOSTUNREACH){
////            cout << "目的主机不可达" << endl;
//            return -1;
//        }
//    }
    //接收ICMP的EchoReply数据报
    iResult = RecvEchoReply(socketRaw, &addrSrc, &addrDest, &stDecodeResult,stdSzDestIP);
//    cout << "RecvEchoReply result" << iResult <<  endl;

    //linux下close(...)
    close(socketRaw);

        //win下
//        closesocket(socketRaw);
//        WSACleanup();

    return 0;

//    //初始化数据包
//    memset(&icmpSendBuff[sizeof(IcmpHeader)],'E',32);

//    USHORT nSeq=0;
//    //接收ICMP包缓存区
//    char revBuf[1024];
//    SOCKADDR_IN from;
//    int nLen=sizeof(from);

//    //填充ICMP包
//    pIcmp->icmp_checksum=0;
//    pIcmp->icmp_timestamp=::GetTickCount();
//    pIcmp->icmp_sequence=nSeq++;
//    pIcmp->icmp_checksum=CheckSum((USHORT *)icmpSendBuff,sizeof(IcmpHeader)+32);


//    //接受回显回答
//    iResult=::recvfrom(socketRaw,revBuf,1024,0,(sockaddr *)&from,&nLen);
//    if (iResult==SOCKET_ERROR)
//    {
//        cout << stdSzDestIP << "response timeout\n";
//        return -1;
//    }
//    cout <<stdSzDestIP <<  "live \n" << endl;

//    //linux下close(...)
//    closesocket(iResult);//win下
//    WSACleanup();//win下
    //    return 0;
}



void MainWindow::startScan()
{

    QString startIp = ui->IPBeginInput->text();
    char* stdStartIp= startIp.toLatin1().data();

//    QString endIp = ui->IPEndInput->text();
//    char* stdEndIP = endIp.toLatin1().data();

//    char* listIP[10];
//    listIP[0]=stdStartIp;
//    char* a = stdStartIp;
//    for(int coutIP=1; coutIP < 5;coutIP++){
//        char* a = increment_address(a);
//        listIP[coutIP] = a;
//    }

//    for (int k = 0; k < 5; k ++) {
//        Ping(listIP[k]);
//    }

//    for( int i=0; i<4; i ++){

    Ping(stdStartIp);

}

