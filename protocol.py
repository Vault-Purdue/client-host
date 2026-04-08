from enum import IntEnum

class MessageID(IntEnum):
    SESSION_OPEN            = 0x00
    KEY_EXCHANGE            = 0x01
    PIN_EXCHANGE            = 0x02
    PIN_ACK                 = 0x03
    SESSION_CLOSE           = 0x0F
    STATUS_QUERY            = 0x20 
    STATUS_RESPONSE         = 0x21 
    FILE_TRANSFER_REQ       = 0x10 
    FILE_START              = 0x11 
    FILE_BLOCK              = 0x12
    FILE_END                = 0x13
    FILE_TRANSFER_COMPLETE  = 0x14
    FILE_REQ_ACK            = 0xF0
    FILE_COMPLETE_ACK       = 0xF2