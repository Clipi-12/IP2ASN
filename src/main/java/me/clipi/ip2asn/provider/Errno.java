package me.clipi.ip2asn.provider;

class Errno {
	private Errno() {
	}

	static final int
		COMMON_READ_UNTIL_PIPE_NUM_OOB = 0,
		COMMON_READ_UNTIL_PIPE_END_OOB = 1,
		COMMON_READ_UNTIL_PIPE_NOT_DIGIT = 2,
		COMMON_READ_UNTIL_PIPE_TOO_MUCH_RECURSION = 3,
		COMMON_READ_UNTIL_PIPE_UNEXPECTED_AFTER_SPACE = 4,
		COMMON_READ_UNTIL_PIPE_NUM_DOESNT_FIT_IN_INT = 5,

	UDP_EXPECTED_END_OF_PACKET = 6,
		UDP_UNREQUESTED_RESPONSE = 7,
		UDP_INCORRECT_HEADER = 8,
		UDP_INCORRECT_QUESTION = 9,
		UDP_INCORRECT_ANSWER = 10,
		UDP_NON_RFC_COMPLIANT_COMPRESSION = 11,
		UDP_INCOMPATIBLE_RDLENGTH_AND_ACTUAL_LENGTH = 12,
		UDP_INCOMPATIBLE_RDLENGTH_AND_RDATA = 13,

	TCP_EXPECTED_END_OF_PACKET = 14,
		TCP_EXPECTED_END_OF_RESPONSE = 15,
		TCP_EXPECTED_BULK_MESSAGE = 16,
		TCP_EXPECTED_CC = 17,
		TCP_NO_LF_FOUND = 18,
		TCP_NO_SEPARATOR_FROM_ASN_TO_IP = 19,
		TCP_NO_SEPARATOR_FROM_IP_TO_CC = 20,
		TCP_NO_SEPARATOR_FROM_CC_TO_ASNAME = 21,
		TCP_UNEXPECTED_ADDITIONAL_FIELD = 22;
}
