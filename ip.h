#pragma once

#include <cstdint>
#include <string>

/*IP 구조체. final : 상속될 수 없음
ip크기:4바이트 
*/
struct Ip final {
	static const int SIZE = 4;

	// constructor
	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	// casting operator 
	operator uint32_t() const { return ip_; } // default 
	explicit operator std::string() const; //출력할때나 필요한. 명시적 변환

	// comparison operator
	bool operator == (const Ip& r) const { return ip_ == r.ip_; }  

	bool isLocalHost() const { // 127.*.*.*
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix == 0x7F;
	}

	bool isBroadcast() const { // 255.255.255.255
		return ip_ == 0xFFFFFFFF;
	}

	bool isMulticast() const { // 224.0.0.0 ~ 239.255.255.255
		uint8_t prefix = (ip_ & 0xFF000000) >> 24;
		return prefix >= 0xE0 && prefix < 0xF0;
	}

protected:
	uint32_t ip_;
};
