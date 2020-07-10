#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <unistd.h>
#include "QDebug"
#include <QHostInfo>
#include <QNetworkInterface>
#include "pcap.h"
#include <net/if.h>    //struct ifreq
#include <sys/ioctl.h> //ioctl、SIOCGIFADDR
#include <sys/socket.h>
#include <netinet/ether.h>    //ETH_P_ALL
#include <netpacket/packet.h> //struct sockaddr_ll
#include <netinet/in.h>
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    netInfo=this->getNetInfo();


    this->ui->label_7->setText(netInfo.at(0));
    this->ui->label_8->setText(netInfo.at(1));
    this->ui->label_9->setText(netInfo.at(2));
    this->ui->label_7->setEnabled(false);
    this->ui->label_8->setEnabled(false);
    this->ui->label_9->setEnabled(false);


}

QList<QString> MainWindow::getNetInfo()
{
    QList<QString> netInfo;
    QString localHostName = QHostInfo::localHostName();

    netInfo.append(localHostName);
    QList<QHostAddress> ipList = QNetworkInterface::allAddresses();
    foreach(QHostAddress ipItem, ipList)
    {
        //只显示以192开头!=192.168.122.1的IP地址
        if(ipItem.protocol()==QAbstractSocket::IPv4Protocol&&ipItem!=QHostAddress::Null
                &&ipItem!=QHostAddress::LocalHost&&ipItem.toString().left(3)=="192"&&ipItem.toString()!="192.168.122.1")
        {

            netInfo.append(ipItem.toString());

        }
    }

    QList<QNetworkInterface> nets = QNetworkInterface::allInterfaces();// 获取所有网络接口列表
    int nCnt = nets.count();
    QString strMacAddr = "";
    for(int i = 0; i < nCnt; i ++)
    {
        // 如果此网络接口被激活并且正在运行并且不是回环地址，则就是我们需要找的Mac地址
        if(nets[i].flags().testFlag(QNetworkInterface::IsUp) && nets[i].flags().testFlag(QNetworkInterface::IsRunning) && !nets[i].flags().testFlag(QNetworkInterface::IsLoopBack))
        {
            strMacAddr = nets[i].hardwareAddress();

            netInfo.append(strMacAddr);
            //          break;
        }
    }
    return netInfo;
}

QList<QString> MainWindow::arpScanner()
{
    QList<QString> ipAndMacAddress;

    //1.创建通信用的原始套接字
    int sock_raw_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    //2. 根据各种协议首部格式构建发送数据报
    unsigned char send_msg[1024] = {
        //--------------组MAC--------14------

        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //dst_mac: FF:FF:FF:FF:FF:FF
        0x00, 0xF4, 0x8D, 0x1F, 0x84, 0xC4, //src_mac: 00:0c:29:76:68:c9

        0x08, 0x06, //类型：0x0806 ARP协议

        //--------------组ARP--------28-----
        0x00, 0x01, 0x08, 0x00, //硬件类型1(以太网地址),协议类型0x0800(IP)
        0x06, 0x04, 0x00, 0x01, //硬件、协议地址分别是6、4，op:(1：arp请求，2：arp应答)

        0x00, 0xf4, 0x8d, 0x1f, 0x84, 0xc4, //发送端的MAC地址
        192, 168, 1, 114,                   //发送端的IP地址
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //目的MAC地址（由于要获取对方的MAC,所以目的MAC置零）
        192, 168, 1                   //target地址
    };

    //3.数据初始化
    struct sockaddr_ll sll;                    //原始套接字地址结构
    struct ifreq req;                          //网络接口地址
    strncpy(req.ifr_name, "wlp3s0", IFNAMSIZ); //指定网卡名称

    //4.将网络接口赋值给原始套接字地址结构
    ioctl(sock_raw_fd, SIOCGIFINDEX, &req);
    bzero(&sll, sizeof(sll));
    sll.sll_ifindex = req.ifr_ifindex;

    //5.发送ARP请求包

    for (int i = 0; i < 255; i++)
    {
        send_msg[41]=i;
        int len = sendto(sock_raw_fd, send_msg, 42, 0, (struct sockaddr *)&sll, sizeof(sll));

        if (len == -1)
        {
            perror("sendto");
        }

        //6.接收对方的ARP应答
        unsigned char recv_msg[1024] = {0};
        recvfrom(sock_raw_fd, recv_msg, sizeof(recv_msg), 0, NULL, NULL);
        if (recv_msg[21] == 2)
        {                           //ARP应答
            char resp_mac[18] = ""; //arp响应的MAC
            char resp_ip[16] = "";  //arp响应的IP

            sprintf(resp_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    recv_msg[22], recv_msg[23], recv_msg[24], recv_msg[25], recv_msg[26], recv_msg[27]);
            sprintf(resp_ip, "%d.%d.%d.%d", recv_msg[28], recv_msg[29], recv_msg[30], recv_msg[31]);
            QString str1 = QString(resp_ip);
            QString str2 = QString(resp_mac);
            qDebug()<<"IP:"+str1+" - MAC:"+str2;
            ipAndMacAddress.append("IP:"+str1+" - MAC:"+str2+"\n");

        }
    }

    return ipAndMacAddress;

}


MainWindow::~MainWindow()
{
    delete ui;
}



void MainWindow::on_pushButton_3_clicked()
{



    QList<QString> ipAndMacAddress=this->arpScanner();

    for(int i=0;i<ipAndMacAddress.length();i++){
        this->ui->textBrowser_2->insertPlainText(ipAndMacAddress.at(i));

    }

    \
}


