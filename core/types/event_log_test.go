package types

import (
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
