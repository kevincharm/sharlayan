const STATE_INITIAL = 0
const STATE_EXPECTING_PAYLOAD = 1
const STATE_EXPECTING_FOOTER = 2

class PacketParser {
    constructor() {
        this.messages = []
        this.state = 0

        this.byteCursor = 0
        this.header = {
            buffer: Buffer.alloc(40),
            len: 0
        }
    }

    parseHeader(bytes) {
        if (this.header.len === 0 &&
            ((bytes[0] === 0x52 &&
            bytes[1] === 0x52) ||
            (bytes[0] === 0 &&
            bytes[1] === 0))) {
            this.header.buffer[0] = bytes[0]
            this.header.buffer[1] = bytes[1]
            this.header.len += 2
        } else {
            console.log('Not a header:', bytes[0].toString(16), bytes[1].toString(16))
        }

        while (this.byteCursor < bytes.length) {
            if (this.header.len >= 2 &&
                this.header.len < 40) {
                this.header.buffer[this.header.len++] = bytes[this.byteCursor]
                console.log('Appending', bytes[this.byteCursor])
            } else if (this.header.len === 40) {
                this.state = STATE_EXPECTING_PAYLOAD
                break
            } else {
                console.error('Parse error, resetting state.')
                this.header.len = 0
                this.state = STATE_INITIAL
                break
            }
            this.byteCursor++
        }
    }

    feed(bytes) {
        this.byteCursor = 0
        switch (this.state) {
        case STATE_INITIAL:
            this.parseHeader(bytes)
            break
        case STATE_EXPECTING_PAYLOAD:
            console.log('Expecting payload, current header:', this.header.buffer)
            break
        case STATE_EXPECTING_FOOTER:
            break
        default:
            // something fucked up
            this.state = STATE_INITIAL
        }
    }
}

module.exports = PacketParser
