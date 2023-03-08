package types

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"log"
	"strings"
	"testing"
)

/**
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.4;

contract eventLogDemo3 {
    mapping(uint256 => address) _owners;
    // error TransferNotOwner();
    // error TransferNotOwner(address sender);

    function transferOwner1(uint256 tokenId, address newOwner) public {
        if(_owners[tokenId] != msg.sender){
            // revert TransferNotOwner();
            revert("Transfer1 Not Owner");
        }
        _owners[tokenId] = newOwner;
    }

    event Log1(address indexed from, uint256 indexed to, uint256 value);
    event Log2(string indexed str, uint256 value);
    event Log3(string);
    function create(address from, uint256 to, uint256 value) public {
        emit Log1(from, to, value);
        emit Log2("this is log2", value);
        emit Log3("this is log3");
    }
}

*/

/**
{
    "id": 3717682842,
    "jsonrpc": "2.0",
    "result": {
        "blockHash": "0xcebd956b77924b3fc45e4f47bb7cb0295c026223aa138be9d2bb4b4d8b536362",
        "blockNumber": "0x37",
        "contractAddress": "0x7e44c62f91d9a96f1555bf393db4d14db6871a58",
        "cumulativeGasUsed": "0x6dca",
        "effectiveGasPrice": "0x13105427",
        "from": "0xc02f2298c64317c6ac6e7c789f6c8e23b30d2b20",
        "gasUsed": "0x6dca",
        "logs": [
            {
                "address": "0x7e44c62f91d9a96f1555bf393db4d14db6871a58",
                "blockHash": "0xcebd956b77924b3fc45e4f47bb7cb0295c026223aa138be9d2bb4b4d8b536362",
                "blockNumber": "0x37",
                "data": "0x00000000000000000000000000000000000000000000000000000000000007e9",
                "logIndex": "0x0",
                "removed": false,
                "topics": [
                    "0x970b0c7c579bd1eafd36d2fc9a1d824f79af49ddcb38d208314f49783cb46de1",
                    "0x000000000000000000000000c02f2298c64317c6ac6e7c789f6c8e23b30d2b20",
                    "0x00000000000000000000000000000000000000000000000000000000000007e7"
                ],
                "transactionHash": "0x5c4897c749744e6610230f507205b55168c96c3ecf4d03e297085a2e5211a117",
                "transactionIndex": "0x0"
            },
            {
                "address": "0x7e44c62f91d9a96f1555bf393db4d14db6871a58",
                "blockHash": "0xcebd956b77924b3fc45e4f47bb7cb0295c026223aa138be9d2bb4b4d8b536362",
                "blockNumber": "0x37",
                "data": "0x00000000000000000000000000000000000000000000000000000000000007e9",
                "logIndex": "0x1",
                "removed": false,
                "topics": [
                    "0x0c231cace93330e81aabd308eaecd9a98302e543efad0c88d0b99732e7c2ef5f",
                    "0x4b4754487dfd581c125f950dacdbc66c719499dcab8aa82ebedc16c1c1d35bf1"
                ],
                "transactionHash": "0x5c4897c749744e6610230f507205b55168c96c3ecf4d03e297085a2e5211a117",
                "transactionIndex": "0x0"
            },
            {
                "address": "0x7e44c62f91d9a96f1555bf393db4d14db6871a58",
                "blockHash": "0xcebd956b77924b3fc45e4f47bb7cb0295c026223aa138be9d2bb4b4d8b536362",
                "blockNumber": "0x37",
                "data": "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c74686973206973206c6f67330000000000000000000000000000000000000000",
                "logIndex": "0x2",
                "removed": false,
                "topics": [
                    "0xb94ec34dfe32a8a7170992a093976368d1e63decf8f0bc0b38a8eb89cc9f95cf"
                ],
                "transactionHash": "0x5c4897c749744e6610230f507205b55168c96c3ecf4d03e297085a2e5211a117",
                "transactionIndex": "0x0"
            }
        ],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000001000000004200000000000000000000000001000000000000000800000000000000000000000000000000000000000000000000000000000001000000000000000000000000010000000018000000008000000000000000000000000800000000000000000004000000000000000080000002000000000000000010000000000000008000000000000000000000000000040000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000004000000000004000000000000000000000100",
        "status": "0x1",
        "to": "0x7e44c62f91d9a96f1555bf393db4d14db6871a58",
        "transactionHash": "0x5c4897c749744e6610230f507205b55168c96c3ecf4d03e297085a2e5211a117",
        "transactionIndex": "0x0",
        "type": "0x2"
    }
}
*/
func TestEventLogTopicIdx0(t *testing.T) {
	// 参数 0xc02f2298c64317c6Ac6e7c789f6C8E23B30d2b20,2023,2025
	sss := crypto.Keccak256Hash([]byte(`Transfer(address,address,uint256)`))
	log.Println(sss.Hex())
	s := crypto.Keccak256Hash([]byte(`demo1(string)`))
	s2 := crypto.Keccak256Hash([]byte(`demo2(string)`))
	log.Println(s.Hex())
	log.Println(s2.Hex())
	h := crypto.Keccak256Hash([]byte(`Log1(address,uint256,uint256)`))
	h2 := crypto.Keccak256Hash([]byte(`Log2(string,uint256)`))
	h3 := crypto.Keccak256([]byte(`Log3(string)`))

	if h.String() != "0x970b0c7c579bd1eafd36d2fc9a1d824f79af49ddcb38d208314f49783cb46de1" {
		t.Fail()
	}
	if h2.String() != "0x0c231cace93330e81aabd308eaecd9a98302e543efad0c88d0b99732e7c2ef5f" {
		t.Fail()
	}
	if hexAlignTo64(hex.EncodeToString(h3)) != "0xb94ec34dfe32a8a7170992a093976368d1e63decf8f0bc0b38a8eb89cc9f95cf" {
		t.Fail()
	}
}

func TestEventLogTopicIdx12(t *testing.T) {
	// 获取topic[1],[2]
	// 参数： 0xc02f2298c64317c6Ac6e7c789f6C8E23B30d2b20,2023,2025
	// 1. 已经是16进制，
	v1 := hexAlignTo64("c02f2298c64317c6ac6e7c789f6c8e23b30d2b20")
	// 2. 数字类型不是16进制转换成16进制。
	v2 := hexAlignTo64(fmt.Sprintf("%x", 2023))
	// 3. 不是数字
	v3 := crypto.Keccak256Hash([]byte("this is log2"))

	if v1 != "0x000000000000000000000000c02f2298c64317c6ac6e7c789f6c8e23b30d2b20" {
		t.Fail()
	}
	if v2 != "0x00000000000000000000000000000000000000000000000000000000000007e7" {
		t.Fail()
	}
	if v3.String() != "0x4b4754487dfd581c125f950dacdbc66c719499dcab8aa82ebedc16c1c1d35bf1" {
		t.Fail()
	}
}

func TestTopEventLogBloom(t *testing.T) {
	/**
	address(T2000138CQwyzFxbWZ59mNjkq3eZ3eH41t7b5midm@0),
	data(0x64656d6f3120706c616365206f6e65),
	topic(0x86ff820a94f2ff6aa28661388f6f765b6e54efb217a2b130f77ce543c7d66571)
	bloom(0x00000000000000040000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000

	*/
	buf := make([]byte, 6)
	bb := []byte("T2000138CQwyzFxbWZ59mNjkq3eZ3eH41t7b5midm@0")
	logs := []Log{
		{
			Topics: []common.Hash{
				common.HexToHash("0x86ff820a94f2ff6aa28661388f6f765b6e54efb217a2b130f77ce543c7d66571"),
			},
		},
	}
	var bin Bloom
	bin.add(bb, buf)
	for _, log := range logs {
		for _, b := range log.Topics {
			bin.add(b[:], buf)
			//t.Log(common.Bytes2Hex(bin.Bytes()))
		}
	}
	t.Log(common.Bytes2Hex(bin.Bytes()))
	// 验证生成的bloom
	if common.Bytes2Hex(bin.Bytes()) != "00000000000000040000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000" {
		t.Fail()
	}
	// 验证能够过滤
	for _, log := range logs {
		for i, topic := range log.Topics {
			if i == 0 {
				continue
			}
			//t.Log(common.Bytes2Hex(topic[:]))
			if bin.Test(topic[:]) == false {
				t.Fatal(common.Bytes2Hex(topic[:]))
			}
		}
	}
}

func TestAbiEncodeString3(t *testing.T) {
	a := struct {
		Target string
		Amount uint64
	}{
		"asdasd",
		123123,
	}
	d, _ := json.Marshal(a)
	fmt.Println(string(d))
	s := []byte(string(d))
	head := Align32HeadAdd0(IntToBytes(32))
	Len := Align32HeadAdd0(IntToBytes(len(s)))
	data := Align32TailAdd0(s)
	head = append(head, Len...)
	head = append(head, data...)
	fmt.Println(hex.EncodeToString(head))

}

func TestAbiEncodeString2(t *testing.T) {
	s := []byte("this is log3")
	target := "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c74686973206973206c6f67330000000000000000000000000000000000000000"
	head := Align32HeadAdd0(IntToBytes(32))
	Len := Align32HeadAdd0(IntToBytes(len(s)))
	data := Align32TailAdd0(s)
	head = append(head, Len...)
	head = append(head, data...)
	fmt.Println(hex.EncodeToString(head))
	if target != "0x"+hex.EncodeToString(head) {
		t.Fail()
	}
}

func TestAbiEncodeString4(t *testing.T) {
	s := []byte("helloworld")
	fmt.Println("str: ", "helloworld", len(s), s)
	head := Align32HeadAdd0(IntToBytes(32))
	Len := Align32HeadAdd0(IntToBytes(len(s)))
	data := Align32TailAdd0(s)
	fmt.Println("head: 32 \t", head, len(head))
	fmt.Println("len: 10 \t", Len, len(Len))
	fmt.Println("data: helloworld \t", data, len(data))
	head = append(head, Len...)
	head = append(head, data...)
	fmt.Println("head+len+data: \t", head, len(head))
	fmt.Println("hex head+len+data: \t", hex.EncodeToString(head), len(hex.EncodeToString(head)))

}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer(make([]byte, 0))
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func Align32HeadAdd0(data []byte) []byte {
	Len := 0
	if len(data)%32 != 0 {
		if len(data) < 32 {
			Len = 32 - len(data)
		} else if len(data) > 32 {
			Len = 32 - (len(data) % 32)
		}
	}
	return append(make([]byte, Len), data...)
}
func Align32TailAdd0(data []byte) []byte {
	Len := 0
	if len(data)%32 != 0 {
		if len(data) < 32 {
			Len = 32 - len(data)
		} else if len(data) > 32 {
			Len = 32 - (len(data) % 32)
		}
	}
	return append(data, make([]byte, Len)...)
}

func TestTopGenLog(t *testing.T) {
	/**
	address(T2000138CQwyzFxbWZ59mNjkq3eZ3eH41t7b5midm@0),
	data(0x64656d6f3120706c616365206f6e65),
	topic(0x86ff820a94f2ff6aa28661388f6f765b6e54efb217a2b130f77ce543c7d66571)
	bloom(0x00000000000000040000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000

	*/
	type Log struct {
		Address string
		Data    string
		Topic   string
	}
	logs := []Log{
		{
			"T200024uHxGKRST3hk5tKFjVpuQbGNDihMJR6qeeQ@2",
			"demo1 one",
			"demo1(string)",
		},
		{
			"T200024uHxGKRST3hk5tKFjVpuQbGNDihMJR6qeeQ@2",
			"demo2 one",
			"demo2(string)",
		},
		{
			"T200024uHxGKRST3hk5tKFjVpuQbGNDihMJR6qeeQ@2",
			"demo1 two",
			"demo1(string)",
		},
	}
	buf := make([]byte, 6)
	var bin Bloom

	for _, v := range logs {
		fmt.Println("address:", v.Address)
		topic := crypto.Keccak256Hash([]byte(v.Topic))
		fmt.Println("topic:", topic.String())
		data := hex.EncodeToString([]byte(v.Data))
		fmt.Println("data:", hexAlignTo64(data))
		bin.add([]byte(v.Address), buf)
		bin.add([]byte(v.Topic), buf)
		fmt.Println()
	}
	d := hex.EncodeToString([]byte("this is log3"))
	fmt.Printf("d:%+v \n", d)
	fmt.Println("bloom:", bin.Bytes())
	s := `0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0 128 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2 0 0 0 0 0 4 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 8 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 8 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4 4 0 16 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0`
	s2 := strings.Replace(s, " ", "", -1)
	fmt.Println(s2)
	ss := "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000c74686973206973206c6f67330000000000000000000000000000000000000000"
	fmt.Println(len(ss))
}

func TestEventLogBloom(t *testing.T) {
	buf := make([]byte, 6)
	logs := []Log{
		{
			Address: common.HexToAddress("0x7e44c62f91d9a96f1555bf393db4d14db6871a58"),
			Topics: []common.Hash{
				common.HexToHash("0x970b0c7c579bd1eafd36d2fc9a1d824f79af49ddcb38d208314f49783cb46de1"),
				common.HexToHash("0x000000000000000000000000c02f2298c64317c6ac6e7c789f6c8e23b30d2b20"),
				common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000007e7"),
			},
		},
		{
			Address: common.HexToAddress("0x7e44c62f91d9a96f1555bf393db4d14db6871a58"),
			Topics: []common.Hash{
				common.HexToHash("0x0c231cace93330e81aabd308eaecd9a98302e543efad0c88d0b99732e7c2ef5f"),
				common.HexToHash("0x4b4754487dfd581c125f950dacdbc66c719499dcab8aa82ebedc16c1c1d35bf1"),
			},
		},
		{
			Address: common.HexToAddress("0x7e44c62f91d9a96f1555bf393db4d14db6871a58"),
			Topics: []common.Hash{
				common.HexToHash("0xb94ec34dfe32a8a7170992a093976368d1e63decf8f0bc0b38a8eb89cc9f95cf"),
			},
		},
	}
	var bin Bloom
	for _, log := range logs {
		bin.add(log.Address.Bytes(), buf)
		for _, b := range log.Topics {
			bin.add(b[:], buf)
			//t.Log(common.Bytes2Hex(bin.Bytes()))
		}
	}
	// 验证生成的bloom
	if common.Bytes2Hex(bin.Bytes()) != "00000000000000000000000000000000000000000000000000000000000001000000004200000000000000000000000001000000000000000800000000000000000000000000000000000000000000000000000000000001000000000000000000000000010000000018000000008000000000000000000000000800000000000000000004000000000000000080000002000000000000000010000000000000008000000000000000000000000000040000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000004000000000004000000000000000000000100" {
		t.Fail()
	}
	// 验证能够过滤
	for _, log := range logs {
		for i, topic := range log.Topics {
			if i == 0 {
				continue
			}
			//t.Log(common.Bytes2Hex(topic[:]))
			if bin.Test(topic[:]) == false {
				t.Fatal(common.Bytes2Hex(topic[:]))
			}
		}
	}
}

func hexAlignTo64(s string) string {
	var zeroN string
	for i := 0; i < 64-len(s); i++ {
		zeroN += "0"
	}
	return "0x" + zeroN + s
}

func TestT2Base58(t *testing.T) {
	s := "04cf18f92067fa05cac30d6dfc9ec1a04ef7391140f377da3d2ce11c0b297997968a25587a06708426e2fd65934fe79132c4b2458b6a68558ce113d43a41689c38"
	s1 := base58.Encode([]byte(s))
	fmt.Println(s1)
	//137Vx3DPdt6tp2UfACRRvXkXheo1tDq589jM
	//1QCaxc8hutpdZ62iKZsn1TCG3nh7uPZojq

	// 之前的值
	vv, _ := hex.DecodeString("04cf18f92067fa05cac30d6dfc9ec1a04ef7391140f377da3d2ce11c0b297997968a25587a06708426e2fd65934fe79132c4b2458b6a68558ce113d43a41689c38")
	fmt.Println(vv)
	dencode := base58.Encode(vv)
	fmt.Println(dencode)
	// 之后的值编码
	// [0 1 48 111 230 75 47 170 20 138 5 199 58 177 23 112 137 38 182 81 18 252 8 215 234 110 144]
	end := base58.Encode([]byte("04cf18f92067fa05cac30d6dfc9ec1a04ef7391140f377da3d2ce11c0b297997968a25587a06708426e2fd65934fe79132c4b2458b6a68558ce113d43a41689c38"))
	fmt.Println(end)
	num, _ := base58.Decode("137Vx3DPdt6tp2UfACRRvXkXheo1tDq589jM")
	fmt.Println("num:", num)
	fmt.Println(hex.EncodeToString(num))
	fmt.Println(hex.EncodeToString([]byte("T0000137Vx3DPdt6tp2UfACRRvXkXheo1tDq589jM")))
	fmt.Println(len("3fc432ccaf8abd5bd725bdfd85fe628aae344f16"))
	fmt.Println("T0000137Vx3DPdt6tp2UfACRRvXkXheo1tDq589jM")
	v, _ := base64.StdEncoding.DecodeString("137Vx3DPdt6tp2UfACRRvXkXheo1tDq589jM")
	fmt.Println(hex.EncodeToString(v))
	fmt.Println(hex.EncodeToString([]byte("T0000137Vx3DPdt6tp2UfACRRvXkXheo1tDq589jM")))
	fmt.Println(hex.EncodeToString([]byte("T0000137Vx3DPdt6tp2UfACRRvXkXheo1tDq589jM")))
	//b4e7a86997ce95ebaa1f9ccf5f9f50dbfb619b75
	//e55ba8ee20757608177616d1d0642de6774d16b0
	//7e55ba8ee20757608177616d1d0642de6774d16b0
	//616d1d0642de6774d16b0
	fmt.Println()
	fmt.Println("T0: ", "LaXD5Ng82ntBsPsGfysHLa2nL8YmqsvTG2")
	ss := crypto.Keccak256Hash([]byte("LaXD5Ng82ntBsPsGfysHLa2nL8YmqsvTG2"))
	fmt.Println("Keccak256Hash: ", ss)
	vvv := ss.Hex()[len(ss.Hex())-40:]
	fmt.Println("0x: ", vvv)
}

//0000000000000000000000007f3ea0ff2cc11fc655f7ca546c2575003dc842c9
//4d4c376f425a6269744243635868724a777142686861324d55696d6436534d395a36
func TestHex(t *testing.T) {
	s := "T20000MTotTKfAJRxrfvEwEJvtgCqzH9GkpMmAUg"
	a := hex.EncodeToString([]byte(s))
	fmt.Println(a)
	fmt.Println(a[len(a)-40:])
	b, _ := hex.DecodeString("0000000000000000000000004577454a76746743717a4839476b704d6d415567")

	fmt.Println(string(b))
}
