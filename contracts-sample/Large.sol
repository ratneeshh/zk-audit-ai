// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract BigVault {
  mapping(address => uint256) public balances;
  uint256 public total;
  function op0(uint256 a) external {
    require(a > 0);
    total += a * 1;
    balances[msg.sender] += a;
  }
  function op1(uint256 a) external {
    require(a > 1);
    total += a * 2;
    balances[msg.sender] += a;
  }
  function op2(uint256 a) external {
    require(a > 2);
    total += a * 3;
    balances[msg.sender] += a;
  }
  function op3(uint256 a) external {
    require(a > 3);
    total += a * 4;
    balances[msg.sender] += a;
  }
  function op4(uint256 a) external {
    require(a > 4);
    total += a * 5;
    balances[msg.sender] += a;
  }
  function op5(uint256 a) external {
    require(a > 5);
    total += a * 6;
    balances[msg.sender] += a;
  }
  function op6(uint256 a) external {
    require(a > 6);
    total += a * 7;
    balances[msg.sender] += a;
  }
  function op7(uint256 a) external {
    require(a > 7);
    total += a * 8;
    balances[msg.sender] += a;
  }
  function op8(uint256 a) external {
    require(a > 8);
    total += a * 9;
    balances[msg.sender] += a;
  }
  function op9(uint256 a) external {
    require(a > 9);
    total += a * 10;
    balances[msg.sender] += a;
  }
  function op10(uint256 a) external {
    require(a > 10);
    total += a * 11;
    balances[msg.sender] += a;
  }
  function op11(uint256 a) external {
    require(a > 11);
    total += a * 12;
    balances[msg.sender] += a;
  }
  function op12(uint256 a) external {
    require(a > 12);
    total += a * 13;
    balances[msg.sender] += a;
  }
  function op13(uint256 a) external {
    require(a > 13);
    total += a * 14;
    balances[msg.sender] += a;
  }
  function op14(uint256 a) external {
    require(a > 14);
    total += a * 15;
    balances[msg.sender] += a;
  }
  function op15(uint256 a) external {
    require(a > 15);
    total += a * 16;
    balances[msg.sender] += a;
  }
  function op16(uint256 a) external {
    require(a > 16);
    total += a * 17;
    balances[msg.sender] += a;
  }
  function op17(uint256 a) external {
    require(a > 17);
    total += a * 18;
    balances[msg.sender] += a;
  }
  function op18(uint256 a) external {
    require(a > 18);
    total += a * 19;
    balances[msg.sender] += a;
  }
  function op19(uint256 a) external {
    require(a > 19);
    total += a * 20;
    balances[msg.sender] += a;
  }
  function op20(uint256 a) external {
    require(a > 20);
    total += a * 21;
    balances[msg.sender] += a;
  }
  function op21(uint256 a) external {
    require(a > 21);
    total += a * 22;
    balances[msg.sender] += a;
  }
  function op22(uint256 a) external {
    require(a > 22);
    total += a * 23;
    balances[msg.sender] += a;
  }
  function op23(uint256 a) external {
    require(a > 23);
    total += a * 24;
    balances[msg.sender] += a;
  }
  function op24(uint256 a) external {
    require(a > 24);
    total += a * 25;
    balances[msg.sender] += a;
  }
  function op25(uint256 a) external {
    require(a > 25);
    total += a * 26;
    balances[msg.sender] += a;
  }
  function op26(uint256 a) external {
    require(a > 26);
    total += a * 27;
    balances[msg.sender] += a;
  }
  function op27(uint256 a) external {
    require(a > 27);
    total += a * 28;
    balances[msg.sender] += a;
  }
  function op28(uint256 a) external {
    require(a > 28);
    total += a * 29;
    balances[msg.sender] += a;
  }
  function op29(uint256 a) external {
    require(a > 29);
    total += a * 30;
    balances[msg.sender] += a;
  }
  function op30(uint256 a) external {
    require(a > 30);
    total += a * 31;
    balances[msg.sender] += a;
  }
  function op31(uint256 a) external {
    require(a > 31);
    total += a * 32;
    balances[msg.sender] += a;
  }
  function op32(uint256 a) external {
    require(a > 32);
    total += a * 33;
    balances[msg.sender] += a;
  }
  function op33(uint256 a) external {
    require(a > 33);
    total += a * 34;
    balances[msg.sender] += a;
  }
  function op34(uint256 a) external {
    require(a > 34);
    total += a * 35;
    balances[msg.sender] += a;
  }
  function op35(uint256 a) external {
    require(a > 35);
    total += a * 36;
    balances[msg.sender] += a;
  }
  function op36(uint256 a) external {
    require(a > 36);
    total += a * 37;
    balances[msg.sender] += a;
  }
  function op37(uint256 a) external {
    require(a > 37);
    total += a * 38;
    balances[msg.sender] += a;
  }
  function op38(uint256 a) external {
    require(a > 38);
    total += a * 39;
    balances[msg.sender] += a;
  }
  function op39(uint256 a) external {
    require(a > 39);
    total += a * 40;
    balances[msg.sender] += a;
  }
  function cashOut(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount;
  }
}
