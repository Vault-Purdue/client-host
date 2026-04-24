from enum import IntEnum

class MessageID(IntEnum):
    SESSION_OPEN            = 0x01
    KEY_EXCHANGE            = 0x02
    PIN_EXCHANGE            = 0x03
    PIN_ACK                 = 0xF2
    SESSION_CLOSE           = 0x0F 
    FILE_TRANSFER_REQ       = 0x20
    FILE_CONTENT            = 0x21
    FILE_REQ_ACK            = 0xF0
    FILE_COMPLETE_ACK       = 0xF1