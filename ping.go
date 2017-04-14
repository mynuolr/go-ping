
package ping

import (
	"net"
	"bytes"
	"encoding/binary"

	"time"
	"strings"
	"strconv"
)

/*
Echo or Echo Reply Message

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
 */
type EchoIcmp struct {
	Type uint8
	Code uint8
	Checksum    uint16
	Identifier  uint16
	SequenceNum uint16

}

type PingData struct {
	Timeout float64
	TTL int
	Online bool
}

func Ping(host string) (PingData,error) {
	conn, err := net.Dial("ip4:icmp",host)
	if err != nil {

		return PingData{},err
	}

	dd,err:=DoPing(conn)
	defer conn.Close()

	return dd,err

}
func (p *EchoIcmp) checkSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)
	p.Checksum= uint16(^sum)
	return  uint16(^sum)
}
func structureICMP(host string) EchoIcmp {
	var icmp     EchoIcmp
	icmp.Type=8
	icmp.Code=1
	icmp.Checksum=0
	hosts := strings.Split(host,".")
	var i int
	var err error
	if i, err = strconv.Atoi(hosts[0]); err != nil {
		icmp.Identifier=0

	}
	icmp.Identifier=uint16(i)
	if i, err = strconv.Atoi(hosts[1]); err != nil {
		icmp.SequenceNum=0

	}
	icmp.SequenceNum=uint16(i)
	return icmp
}

/*
icmp转成字节数组
@bytelen 附加数据包长度
 */
func (p *EchoIcmp)toBytes(byteLen int) []byte {
	var buffer  bytes.Buffer
	binary.Write(&buffer,binary.BigEndian,p)
	//数据包
	var newByte = make([]byte,byteLen)
	buffer.Write(newByte)
	//校验位
	p.checkSum(buffer.Bytes())
	//重新填充数据包
	buffer.Reset()
	binary.Write(&buffer,binary.BigEndian,p)
	buffer.Write(newByte)
	return buffer.Bytes()
}

func DoPing(conn net.Conn) (PingData,error) {
	icmp:=structureICMP(conn.RemoteAddr().String())
	senddata:=icmp.toBytes(32)
	//发送
	starttime := time.Now() //计时
	if _, err := conn.Write(senddata); err != nil {
		return PingData{},err
	}
	conn.SetReadDeadline((time.Now().Add(time.Second * 5)))
	//ip 头 + icmp 头8 + data （可以去掉data）
	ECHO_REPLY_HEAD_LEN:=20
	var receive []byte = make([]byte, ECHO_REPLY_HEAD_LEN+8+32)
	_, err :=conn.Read(receive)
	//记录收到数据包得时间
	endduration := float64(time.Since(starttime))/ (1000 * 1000)
	var (
		online = true
		ttl=int(receive[8])
	)
	if err != nil || receive[ECHO_REPLY_HEAD_LEN+4] != senddata[4] || receive[ECHO_REPLY_HEAD_LEN+5] != senddata[5] || receive[ECHO_REPLY_HEAD_LEN+6] != senddata[6] || receive[ECHO_REPLY_HEAD_LEN+7] != senddata[7] || endduration >= float64(1000) || receive[ECHO_REPLY_HEAD_LEN] == 11 {
		online=false
		ttl=-1

	}
	return PingData{endduration,ttl,online},nil
}